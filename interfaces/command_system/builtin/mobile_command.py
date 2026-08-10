#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Pair and manage KittySploit mobile clients from the live console."""

from __future__ import annotations

import argparse
import hashlib
import secrets
import socket
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from core.output_handler import print_error, print_info, print_success, print_warning
from interfaces.command_system.base_command import BaseCommand


class MobileCommand(BaseCommand):
    @property
    def name(self) -> str:
        return "mobile"

    @property
    def description(self) -> str:
        return "Pair and manage the KittySploit mobile app (under construction)"

    @property
    def usage(self) -> str:
        return (
            "mobile pair [--host HOST] [--port PORT] [--advertise-host HOST] "
            "[--ttl SECONDS] [--insecure-http] | mobile status | mobile revoke DEVICE_ID"
        )

    @property
    def help_text(self) -> str:
        return """
Pair the KittySploit mobile app with this running framework.

Note: the mobile feature is under construction — pairing UI and QR work, but the app
experience is still incomplete.

Subcommands:
    pair      Start the local mobile API if needed and display a one-time QR code
    status    Show the API endpoint, pending pairings, and paired devices
    revoke    Revoke every token belonging to one paired device

Pair options:
    --host HOST             Listening interface (default: 0.0.0.0)
    --port PORT             Listening port (default: 5000)
    --advertise-host HOST   Address reachable by the phone (auto-detected by default)
    --ttl SECONDS           QR lifetime, from 30 to 600 seconds (default: 120)
    --insecure-http         Disable TLS; use only on a trusted isolated network

Examples:
    mobile pair
    mobile pair --advertise-host 192.168.1.42
    mobile status
    mobile revoke 8f31c4...
        """

    def get_subcommands(self) -> List[str]:
        return ["pair", "status", "revoke", "help"]

    def execute(self, args: List[str], **kwargs) -> bool:
        print_warning(
            "Mobile is under construction — QR pairing works, but the feature is not finished yet."
        )
        if not args:
            return self._pair([])
        subcommand = args[0].lower()
        rest = args[1:]
        if subcommand in ("help", "-h", "--help"):
            self.show_help()
            return True
        if subcommand == "pair":
            return self._pair(rest)
        if subcommand == "status":
            return self._status()
        if subcommand == "revoke":
            return self._revoke(rest)
        print_error(f"Unknown subcommand: {subcommand}")
        print_info("Use: mobile pair|status|revoke|help")
        return False

    def _state(self) -> Optional[Dict[str, Any]]:
        return getattr(self.framework, "_mobile_console", None)

    def _set_state(self, state: Dict[str, Any]) -> None:
        self.framework._mobile_console = state

    def _pair(self, args: List[str]) -> bool:
        parser = argparse.ArgumentParser(prog="mobile pair", add_help=True)
        parser.add_argument("--host", default="0.0.0.0")
        parser.add_argument("--port", type=int, default=5000)
        parser.add_argument("--advertise-host")
        parser.add_argument("--ttl", type=int, default=120)
        parser.add_argument("--insecure-http", action="store_true")
        try:
            parsed = parser.parse_args(args)
        except SystemExit:
            return False
        if not 1 <= parsed.port <= 65535:
            print_error("Port must be between 1 and 65535.")
            return False
        if not 30 <= parsed.ttl <= 600:
            print_error("Pairing TTL must be between 30 and 600 seconds.")
            return False

        advertise_host = parsed.advertise_host or self._local_address()
        try:
            state = self._ensure_server(
                host=parsed.host,
                port=parsed.port,
                advertise_host=advertise_host,
                insecure_http=parsed.insecure_http,
            )
            pairing = state["manager"].create_pairing(
                state["base_url"],
                certificate_sha256=state.get("certificate_sha256"),
                ttl_seconds=parsed.ttl,
            )
        except Exception as exc:
            print_error(f"Unable to start mobile pairing: {exc}")
            return False

        print_success("Mobile pairing is ready")
        print_info(f"Endpoint: {pairing['api_base_url']}")
        print_info(f"Expires in: {pairing['expires_in']} seconds")
        self._print_qr(pairing["pairing_uri"])
        print_info(f"Pairing link: {pairing['pairing_uri']}")
        if parsed.insecure_http:
            print_warning("TLS is disabled. Pair only on a trusted isolated network.")
        else:
            print_info("The certificate fingerprint is embedded in the QR for pinning.")
        return True

    def _ensure_server(
        self,
        *,
        host: str,
        port: int,
        advertise_host: str,
        insecure_http: bool,
    ) -> Dict[str, Any]:
        existing = self._state()
        if existing and existing.get("server") and existing["server"].running:
            if existing["host"] != host or existing["port"] != port:
                raise RuntimeError(
                    f"mobile API already listens on {existing['host']}:{existing['port']}"
                )
            if existing.get("advertise_host") != advertise_host:
                raise RuntimeError(
                    "mobile API is already running with advertised host "
                    f"{existing.get('advertise_host')}; restart KittySploit to change it"
                )
            if existing.get("insecure_http") != insecure_http:
                raise RuntimeError(
                    "mobile API transport is already configured; restart KittySploit to change TLS mode"
                )
            return existing

        from interfaces.api_server import ApiServer
        from interfaces.mobile_pairing import MobilePairingManager

        self._assert_port_available(host, port)

        ssl_context = None
        fingerprint = None
        if not insecure_http:
            from interfaces.server_tls import (
                DEFAULT_TLS_DIR,
                build_server_ssl_context,
                generate_self_signed_cert,
            )

            cert_path, key_path = generate_self_signed_cert(
                output_dir=Path(DEFAULT_TLS_DIR) / "mobile",
                common_name=advertise_host,
                force=True,
            )
            ssl_context = build_server_ssl_context(cert_path, key_path)
            fingerprint = self._certificate_fingerprint(cert_path)

        scheme = "http" if insecure_http else "https"
        display_host = self._url_host(advertise_host)
        base_url = f"{scheme}://{display_host}:{port}"
        server = ApiServer(
            self.framework,
            host=host,
            port=port,
            api_key=secrets.token_urlsafe(32),
            ssl_context=ssl_context,
        )
        manager = MobilePairingManager(server.token_manager)
        server.mobile_pairing_manager = manager
        server.start()
        state = {
            "server": server,
            "manager": manager,
            "host": host,
            "port": port,
            "advertise_host": advertise_host,
            "insecure_http": insecure_http,
            "base_url": base_url,
            "certificate_sha256": fingerprint,
            "started_at": time.time(),
        }
        self._set_state(state)
        return state

    def _status(self) -> bool:
        state = self._state()
        if not state or not state.get("server") or not state["server"].running:
            print_info("Mobile API is not running. Use 'mobile pair' to start it.")
            return True
        manager = state["manager"]
        devices = manager.list_devices()
        print_success(f"Mobile API running at {state['base_url']}")
        print_info(f"Pending pairing codes: {manager.pending_count()}")
        if not devices:
            print_info("No mobile device has been paired yet.")
            return True
        for device in devices:
            status = "revoked" if device["revoked"] else "active"
            print_info(
                f"{device['id']}  {device['name']}  {status}  paired {device['paired_at']}"
            )
        return True

    def _revoke(self, args: List[str]) -> bool:
        if len(args) != 1:
            print_error("Usage: mobile revoke DEVICE_ID")
            return False
        state = self._state()
        if not state:
            print_error("Mobile API is not running.")
            return False
        device_id = args[0]
        if not state["manager"].revoke_device(device_id):
            print_error(f"Unknown or already revoked device: {device_id}")
            return False
        print_success(f"Mobile device revoked: {device_id}")
        return True

    @staticmethod
    def _local_address() -> str:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.connect(("192.0.2.1", 9))
            address = sock.getsockname()[0]
            if address and not address.startswith("127."):
                return address
        except OSError:
            pass
        finally:
            sock.close()
        try:
            return socket.gethostbyname(socket.gethostname())
        except OSError:
            return "127.0.0.1"

    @staticmethod
    def _url_host(host: str) -> str:
        return f"[{host}]" if ":" in host and not host.startswith("[") else host

    @staticmethod
    def _assert_port_available(host: str, port: int) -> None:
        family = socket.AF_INET6 if ":" in host else socket.AF_INET
        probe = socket.socket(family, socket.SOCK_STREAM)
        try:
            probe.bind((host, port))
        except OSError as exc:
            raise RuntimeError(f"cannot listen on {host}:{port}: {exc}") from exc
        finally:
            probe.close()

    @staticmethod
    def _certificate_fingerprint(cert_path: Path) -> str:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes

        certificate = x509.load_pem_x509_certificate(cert_path.read_bytes())
        return certificate.fingerprint(hashes.SHA256()).hex()

    @staticmethod
    def _print_qr(value: str) -> None:
        try:
            import qrcode

            qr = qrcode.QRCode(border=1)
            qr.add_data(value)
            qr.make(fit=True)
            qr.print_ascii(invert=True)
        except ImportError:
            print_warning("QR rendering unavailable; install the 'qrcode' dependency.")
