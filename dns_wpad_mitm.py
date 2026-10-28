#!/usr/bin/env python3
"""
DNS server with a local A-record override and upstream DNS forwarding.

Behavior:
    - Listen on a configurable IP and port (default: 0.0.0.0:5454).
    - Answer A queries locally when the first DNS label is "wpad".
    - Forward all other queries to the configured upstream resolver.
    - Support UDP and TCP DNS.
    - Log the hostname, query type, client, transport, and action.

Colors:
    Green      : Local DNS override
    Light gray : Forwarded DNS queries and responses
    Yellow     : Warnings
    Red        : Errors

Requirements:
    Python >= 3.9
    Scapy >= 2.8.0

Install:
    python -m pip install --upgrade scapy

Example:
    python dns_server.py \
        --listen 0.0.0.0 \
        --port 5454 \
        --upstream 1.1.1.1 \
        --answer-ip 192.168.1.100 \
        --log-level DEBUG
"""

from __future__ import annotations

import argparse
import ipaddress
import logging
import os
import socket
import socketserver
import struct
import sys
import threading

from typing import Optional

from scapy.layers.dns import DNS, DNSQR, DNSRR


# ============================================================
# Constants
# ============================================================

LOCAL_LABEL = b"wpad"

DNS_HEADER_SIZE = 12
DNS_MAX_UDP_SIZE = 65535
DNS_MAX_TCP_SIZE = 65535

DNS_TYPE_A = 1
DNS_CLASS_IN = 1

LOG = logging.getLogger("dns_server")


# ============================================================
# Colored logging
# ============================================================

RESET = "\033[0m"

# ANSI colors
GREEN = "\033[32m"
LIGHT_GRAY = "\033[37m"
YELLOW = "\033[33m"
RED = "\033[31m"


class ColoredFormatter(logging.Formatter):
    """Apply colors according to the DNS operation and log level."""

    def __init__(self, fmt: str, use_colors: bool = True):
        super().__init__(fmt)
        self.use_colors = use_colors

    def format(self, record: logging.LogRecord) -> str:
        message = super().format(record)

        if not self.use_colors:
            return message

        # Errors always take precedence.
        if record.levelno >= logging.ERROR:
            color = RED

        elif record.levelno >= logging.WARNING:
            color = YELLOW

        # Local overrides are green.
        elif getattr(record, "dns_local", False):
            color = GREEN

        # Forwarded queries and their responses are light gray.
        elif getattr(record, "dns_forwarded", False):
            color = LIGHT_GRAY

        else:
            color = LIGHT_GRAY

        return f"{color}{message}{RESET}"


def configure_logging(level: str) -> None:
    """Configure colored logging."""

    use_colors = (
        sys.stderr.isatty()
        and "NO_COLOR" not in os.environ
    )

    handler = logging.StreamHandler(sys.stderr)

    handler.setFormatter(
        ColoredFormatter(
            "%(asctime)s %(levelname)s %(name)s: %(message)s",
            use_colors=use_colors,
        )
    )

    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(getattr(logging, level))


# ============================================================
# DNS utilities
# ============================================================

class DNSProxyError(Exception):
    """Raised when an upstream DNS request fails."""


def read_exact(sock: socket.socket, size: int) -> bytes:
    """Read exactly size bytes from a TCP socket."""

    chunks = []
    remaining = size

    while remaining > 0:
        chunk = sock.recv(remaining)

        if not chunk:
            raise ConnectionError(
                "Connection closed before DNS message completed"
            )

        chunks.append(chunk)
        remaining -= len(chunk)

    return b"".join(chunks)


def parse_dns_packet(data: bytes) -> DNS:
    """Parse a DNS packet and validate its basic structure."""

    if len(data) < DNS_HEADER_SIZE:
        raise ValueError("DNS packet is shorter than its header")

    packet = DNS(data)

    if packet.qr != 0:
        raise ValueError("Expected a DNS query, received a response")

    return packet


def get_hostname(packet: DNS) -> str:
    """Return the first question's normalized hostname."""

    try:
        if not packet.qd:
            return "<no-question>"

        qname = packet.qd.qname

        if isinstance(qname, bytes):
            hostname = qname.decode("ascii", errors="replace")
        else:
            hostname = str(qname)

        # DNS names are case-insensitive.
        hostname = hostname.rstrip(".").lower()

        return hostname or "."

    except Exception:
        return "<unavailable>"


def get_query_type(packet: DNS) -> str:
    """Return a readable DNS query type."""

    try:
        if not packet.qd:
            return "<unknown>"

        qtype = int(packet.qd.qtype)

        # Common DNS record types.
        types = {
            1: "A",
            2: "NS",
            5: "CNAME",
            6: "SOA",
            12: "PTR",
            15: "MX",
            16: "TXT",
            28: "AAAA",
            33: "SRV",
            35: "NAPTR",
            41: "OPT",
            43: "DS",
            46: "RRSIG",
            47: "NSEC",
            48: "DNSKEY",
            52: "TLSA",
            64: "SVCB",
            65: "HTTPS",
            255: "ANY",
        }

        return types.get(qtype, f"TYPE{qtype}")

    except Exception:
        return "<unknown>"


def is_local_query(packet: DNS) -> bool:
    try:
        question = packet.qd

        if not question:
            return False

        qname = question.qname

        if int(packet.opcode) != 0:
            return False

        if int(packet.qdcount or 0) != 1:
            return False

        if int(question.qtype) != 1:
            return False

        if int(question.qclass) != 1:
            return False

        if isinstance(qname, bytes):
            hostname = qname.decode("ascii").rstrip(".").lower()
        else:
            hostname = str(qname).rstrip(".").lower()

        first_label = hostname.split(".", 1)[0]

        return first_label == "wpad"

    except Exception as exc:
        return False


# ============================================================
# DNS proxy
# ============================================================

class DNSProxy:

    def __init__(
        self,
        upstream_host: str,
        upstream_port: int,
        answer_ip: str,
        upstream_timeout: float = 3.0,
        local_ttl: int = 60,
    ):
        self.upstream_host = upstream_host
        self.upstream_port = upstream_port
        self.answer_ip = str(ipaddress.IPv4Address(answer_ip))
        self.upstream_timeout = upstream_timeout
        self.local_ttl = local_ttl

    # --------------------------------------------------------
    # Local response
    # --------------------------------------------------------

    def local_response(self, query: DNS) -> bytes:
        """Build a local A-record response."""

        question = query.qd

        response = DNS(
            id=query.id,
            qr=1,
            opcode=query.opcode,
            aa=1,
            tc=0,
            rd=query.rd,
            ra=0,
            z=0,
            ad=0,
            cd=query.cd,
            rcode=0,
            qd=question,
            an=DNSRR(
                rrname=question.qname,
                type="A",
                rclass="IN",
                ttl=self.local_ttl,
                rdata=self.answer_ip,
            ),
        )

        return bytes(response)

    # --------------------------------------------------------
    # Error response
    # --------------------------------------------------------

    @staticmethod
    def servfail(query: DNS) -> bytes:
        """Build a DNS SERVFAIL response."""

        try:
            response = DNS(
                id=query.id,
                qr=1,
                opcode=query.opcode,
                aa=0,
                tc=0,
                rd=query.rd,
                ra=1,
                z=0,
                ad=0,
                cd=query.cd,
                rcode=2,
                qd=query.qd,
            )

            return bytes(response)

        except Exception:
            LOG.exception("Failed to construct SERVFAIL response")
            return b""

    # --------------------------------------------------------
    # UDP forwarding
    # --------------------------------------------------------

    def forward_udp(self, data: bytes) -> bytes:
        """Forward a query to the upstream resolver over UDP."""

        try:
            addresses = socket.getaddrinfo(
                self.upstream_host,
                self.upstream_port,
                type=socket.SOCK_DGRAM,
            )

        except socket.gaierror as exc:
            raise DNSProxyError(
                f"Cannot resolve upstream {self.upstream_host}: {exc}"
            ) from exc

        if not addresses:
            raise DNSProxyError("No upstream addresses found")

        last_error = None

        for family, socktype, proto, _, address in addresses:
            try:
                with socket.socket(family, socktype, proto) as upstream:
                    upstream.settimeout(self.upstream_timeout)
                    upstream.connect(address)
                    upstream.sendall(data)

                    response = upstream.recv(DNS_MAX_UDP_SIZE)

                    if len(response) < DNS_HEADER_SIZE:
                        raise DNSProxyError(
                            "Upstream returned an incomplete DNS response"
                        )

                    return response

            except (OSError, DNSProxyError) as exc:
                last_error = exc

                LOG.debug(
                    "UDP upstream %s:%d failed: %s",
                    self.upstream_host,
                    self.upstream_port,
                    exc,
                )

        raise DNSProxyError(
            f"All upstream UDP addresses failed: {last_error}"
        )

    # --------------------------------------------------------
    # TCP forwarding
    # --------------------------------------------------------

    def forward_tcp(self, data: bytes) -> bytes:
        """Forward a query to the upstream resolver over TCP."""

        try:
            addresses = socket.getaddrinfo(
                self.upstream_host,
                self.upstream_port,
                type=socket.SOCK_STREAM,
            )

        except socket.gaierror as exc:
            raise DNSProxyError(
                f"Cannot resolve upstream {self.upstream_host}: {exc}"
            ) from exc

        if not addresses:
            raise DNSProxyError("No upstream addresses found")

        last_error = None

        for family, socktype, proto, _, address in addresses:
            try:
                with socket.socket(family, socktype, proto) as upstream:
                    upstream.settimeout(self.upstream_timeout)
                    upstream.connect(address)

                    # DNS over TCP uses a two-byte length prefix.
                    upstream.sendall(
                        struct.pack("!H", len(data)) + data
                    )

                    prefix = read_exact(upstream, 2)

                    response_length = struct.unpack(
                        "!H", prefix
                    )[0]

                    if response_length < DNS_HEADER_SIZE:
                        raise DNSProxyError(
                            "Upstream returned an incomplete DNS response"
                        )

                    return read_exact(upstream, response_length)

            except (OSError, DNSProxyError, ConnectionError) as exc:
                last_error = exc

                LOG.debug(
                    "TCP upstream %s:%d failed: %s",
                    self.upstream_host,
                    self.upstream_port,
                    exc,
                )

        raise DNSProxyError(
            f"All upstream TCP addresses failed: {last_error}"
        )

    # --------------------------------------------------------
    # Response validation
    # --------------------------------------------------------

    @staticmethod
    def validate_response(query: DNS, response_data: bytes) -> DNS:
        """Validate the upstream DNS response."""

        if len(response_data) < DNS_HEADER_SIZE:
            raise DNSProxyError("Upstream response is too short")

        response = DNS(response_data)

        if int(response.qr) != 1:
            raise DNSProxyError(
                "Upstream packet is not a DNS response"
            )

        if int(response.id) != int(query.id):
            raise DNSProxyError(
                "Upstream transaction ID mismatch"
            )

        if int(response.opcode) != int(query.opcode):
            raise DNSProxyError(
                "Upstream opcode mismatch"
            )

        # A standard single-question query should receive a matching
        # question in the response.
        if int(query.qdcount or 0) == 1:
            if not response.qd:
                raise DNSProxyError(
                    "Upstream response is missing its question"
                )

            original = query.qd
            returned = response.qd

            original_name = original.qname
            returned_name = returned.qname

            if isinstance(original_name, bytes):
                original_name = original_name.lower().rstrip(b".")

            if isinstance(returned_name, bytes):
                returned_name = returned_name.lower().rstrip(b".")

            if original_name != returned_name:
                raise DNSProxyError(
                    "Upstream question name mismatch"
                )

            if int(original.qtype) != int(returned.qtype):
                raise DNSProxyError(
                    "Upstream question type mismatch"
                )

            if int(original.qclass) != int(returned.qclass):
                raise DNSProxyError(
                    "Upstream question class mismatch"
                )

        return response

    # --------------------------------------------------------
    # Main processing
    # --------------------------------------------------------

    def process(
        self,
        data: bytes,
        transport: str,
        client: str = "unknown",
    ) -> Optional[bytes]:
        """Process one DNS request."""

        try:
            query = parse_dns_packet(data)

        except Exception as exc:
            LOG.error(
                "transport=%s client=%s hostname=<unavailable> "
                "action=DROP error=%s",
                transport.upper(),
                client,
                exc,
            )

            return None

        hostname = get_hostname(query)
        query_type = get_query_type(query)

        query_class = (
            str(int(query.qd.qclass))
            if query.qd
            else "<unknown>"
        )

        log_context = (
            f"hostname={hostname} "
            f"query_type={query_type} "
            f"class={query_class} "
            f"transport={transport.upper()} "
            f"client={client} "
            f"id=0x{int(query.id):04x}"
        )

        LOG.debug(
            "%s action=RECEIVED",
            log_context,
        )

        # ----------------------------------------------------
        # Local override
        # ----------------------------------------------------

        if is_local_query(query):
            LOG.info(
                "%s action=LOCAL_OVERRIDE answer=%s",
                log_context,
                self.answer_ip,
                extra={"dns_local": True},
            )

            try:
                return self.local_response(query)

            except Exception as exc:
                LOG.error(
                    "%s action=LOCAL_ERROR error=%s",
                    log_context,
                    exc,
                )

                return self.servfail(query)

        # ----------------------------------------------------
        # Forward to upstream
        # ----------------------------------------------------

        LOG.info(
            "%s action=FORWARD upstream=%s:%d",
            log_context,
            self.upstream_host,
            self.upstream_port,
            extra={"dns_forwarded": True},
        )

        try:
            if transport.lower() == "tcp":
                response_data = self.forward_tcp(data)

            else:
                response_data = self.forward_udp(data)

            response = self.validate_response(
                query,
                response_data,
            )

            # Retry over TCP if the UDP response was truncated.
            if transport.lower() == "udp" and int(response.tc):
                LOG.info(
                    "%s action=RETRY_TCP reason=TRUNCATED_RESPONSE",
                    log_context,
                    extra={"dns_forwarded": True},
                )

                response_data = self.forward_tcp(data)

                response = self.validate_response(
                    query,
                    response_data,
                )

            LOG.debug(
                "%s action=UPSTREAM_RESPONSE rcode=%d answers=%d",
                log_context,
                int(response.rcode),
                int(response.ancount),
                extra={"dns_forwarded": True},
            )

            return response_data

        except Exception as exc:
            LOG.error(
                "%s action=UPSTREAM_ERROR error=%s",
                log_context,
                exc,
            )

            return self.servfail(query)


# ============================================================
# Bounded concurrent servers
# ============================================================

class BoundedThreadingMixIn(socketserver.ThreadingMixIn):
    """Threaded server with a maximum number of concurrent handlers."""

    daemon_threads = True
    block_on_close = False
    max_workers = 128

    def __init__(self, *args, **kwargs):
        self._worker_slots = threading.BoundedSemaphore(
            self.max_workers
        )

        super().__init__(*args, **kwargs)

    def process_request(self, request, client_address):
        if not self._worker_slots.acquire(blocking=False):
            LOG.warning(
                "Worker limit reached; dropping request from %s",
                client_address,
            )

            self.shutdown_request(request)
            return

        try:
            super().process_request(
                request,
                client_address,
            )

        except Exception:
            self._worker_slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(
                request,
                client_address,
            )

        finally:
            self._worker_slots.release()


# ============================================================
# UDP handler
# ============================================================

class UDPHandler(socketserver.BaseRequestHandler):

    def handle(self):
        data, sock = self.request

        if len(data) < DNS_HEADER_SIZE:
            LOG.error(
                "client=%s transport=UDP action=DROP "
                "error=SHORT_DNS_PACKET",
                self.client_address,
            )
            return

        client = (
            f"{self.client_address[0]}:"
            f"{self.client_address[1]}"
        )

        response = self.server.proxy.process(
            data,
            "udp",
            client,
        )

        if response:
            try:
                sock.sendto(
                    response,
                    self.client_address,
                )

            except OSError as exc:
                LOG.error(
                    "client=%s transport=UDP action=SEND_ERROR error=%s",
                    client,
                    exc,
                )


# ============================================================
# TCP handler
# ============================================================

class TCPHandler(socketserver.BaseRequestHandler):

    def handle(self):
        conn = self.request
        conn.settimeout(self.server.client_timeout)

        client = (
            f"{self.client_address[0]}:"
            f"{self.client_address[1]}"
        )

        try:
            # A TCP connection can carry multiple DNS requests.
            while True:
                try:
                    prefix = read_exact(conn, 2)

                except ConnectionError:
                    return

                length = struct.unpack("!H", prefix)[0]

                if length < DNS_HEADER_SIZE:
                    LOG.error(
                        "client=%s transport=TCP action=DROP "
                        "error=INVALID_DNS_LENGTH length=%d",
                        client,
                        length,
                    )
                    return

                data = read_exact(conn, length)

                response = self.server.proxy.process(
                    data,
                    "tcp",
                    client,
                )

                if not response:
                    return

                if len(response) > DNS_MAX_TCP_SIZE:
                    LOG.error(
                        "client=%s transport=TCP action=DROP "
                        "error=RESPONSE_TOO_LARGE",
                        client,
                    )
                    return

                conn.sendall(
                    struct.pack("!H", len(response)) + response
                )

        except (OSError, TimeoutError, ConnectionError) as exc:
            LOG.debug(
                "client=%s transport=TCP action=DISCONNECT reason=%s",
                client,
                exc,
            )


# ============================================================
# Server classes
# ============================================================

class UDPDNSServer(
    BoundedThreadingMixIn,
    socketserver.UDPServer,
):
    allow_reuse_address = True
    max_workers = 128

    def __init__(self, address, proxy):
        self.proxy = proxy

        super().__init__(
            address,
            UDPHandler,
        )


class TCPDNSServer(
    BoundedThreadingMixIn,
    socketserver.TCPServer,
):
    allow_reuse_address = True
    max_workers = 128
    client_timeout = 10.0

    def __init__(self, address, proxy):
        self.proxy = proxy

        super().__init__(
            address,
            TCPHandler,
        )


# ============================================================
# Command-line arguments
# ============================================================

def parse_args():
    parser = argparse.ArgumentParser(
        description=(
            "DNS server with a local wpad A-record override "
            "and upstream DNS forwarding"
        )
    )

    parser.add_argument(
        "--listen",
        default="0.0.0.0",
        help="Listening IP address (default: 0.0.0.0)",
    )

    parser.add_argument(
        "--port",
        type=int,
        default=5454,
        help="Listening port (default: 5454)",
    )

    parser.add_argument(
        "--upstream",
        default="1.1.1.1",
        help="Upstream DNS server (default: 1.1.1.1)",
    )

    parser.add_argument(
        "--upstream-port",
        type=int,
        default=53,
        help="Upstream DNS port (default: 53)",
    )

    parser.add_argument(
        "--answer-ip",
        default="127.0.0.1",
        help="IPv4 address returned for local A queries",
    )

    parser.add_argument(
        "--timeout",
        type=float,
        default=3.0,
        help="Upstream timeout in seconds (default: 3)",
    )

    parser.add_argument(
        "--ttl",
        type=int,
        default=60,
        help="Local A-record TTL in seconds (default: 60)",
    )

    parser.add_argument(
        "--workers",
        type=int,
        default=128,
        help="Maximum concurrent handlers per transport",
    )

    parser.add_argument(
        "--log-level",
        choices=(
            "DEBUG",
            "INFO",
            "WARNING",
            "ERROR",
            "CRITICAL",
        ),
        default="INFO",
        help="Logging verbosity (default: INFO)",
    )

    args = parser.parse_args()

    if not 1 <= args.port <= 65535:
        parser.error("--port must be between 1 and 65535")

    if not 1 <= args.upstream_port <= 65535:
        parser.error(
            "--upstream-port must be between 1 and 65535"
        )

    if args.timeout <= 0:
        parser.error("--timeout must be positive")

    if args.ttl < 0:
        parser.error("--ttl cannot be negative")

    if args.workers < 1:
        parser.error("--workers must be at least 1")

    try:
        ipaddress.IPv4Address(args.answer_ip)

    except ipaddress.AddressValueError as exc:
        parser.error(
            f"--answer-ip must be a valid IPv4 address: {exc}"
        )

    return args


# ============================================================
# Main
# ============================================================

def main():
    args = parse_args()

    configure_logging(args.log_level)

    UDPDNSServer.max_workers = args.workers
    TCPDNSServer.max_workers = args.workers

    proxy = DNSProxy(
        upstream_host=args.upstream,
        upstream_port=args.upstream_port,
        answer_ip=args.answer_ip,
        upstream_timeout=args.timeout,
        local_ttl=args.ttl,
    )

    udp_server = None
    tcp_server = None

    udp_thread = None
    tcp_thread = None

    try:
        # Bind UDP and TCP to the same port.
        udp_server = UDPDNSServer(
            (args.listen, args.port),
            proxy,
        )

        try:
            tcp_server = TCPDNSServer(
                (args.listen, args.port),
                proxy,
            )

        except Exception:
            udp_server.server_close()
            udp_server = None
            raise

        LOG.info(
            "Listening on %s:%d (UDP/TCP)",
            args.listen,
            args.port,
        )

        LOG.info(
            "Local override: first label '%s' -> %s",
            LOCAL_LABEL.decode(),
            args.answer_ip,
        )

        LOG.info(
            "Upstream resolver: %s:%d",
            args.upstream,
            args.upstream_port,
        )

        LOG.info(
            "Maximum workers per transport: %d",
            args.workers,
        )

        udp_thread = threading.Thread(
            target=udp_server.serve_forever,
            name="dns-udp",
            daemon=True,
        )

        tcp_thread = threading.Thread(
            target=tcp_server.serve_forever,
            name="dns-tcp",
            daemon=True,
        )

        udp_thread.start()
        tcp_thread.start()

        while udp_thread.is_alive() and tcp_thread.is_alive():
            udp_thread.join(timeout=1.0)
            tcp_thread.join(timeout=1.0)

    except KeyboardInterrupt:
        LOG.info("Shutdown requested")

    except OSError:
        LOG.exception("Failed to start DNS server")
        sys.exit(1)

    finally:
        # shutdown() must only be called after serve_forever() starts.
        if udp_server is not None:
            if udp_thread is not None and udp_thread.is_alive():
                udp_server.shutdown()

            udp_server.server_close()

        if tcp_server is not None:
            if tcp_thread is not None and tcp_thread.is_alive():
                tcp_server.shutdown()

            tcp_server.server_close()

        LOG.info("DNS server stopped")


if __name__ == "__main__":
    main()
