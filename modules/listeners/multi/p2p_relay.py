#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
P2P Relay Listener (operator side)

The rendezvous hub runs standalone — no framework required:
  kittyrelay --host 0.0.0.0 --port 9000
  python -m lib.relay
  python scripts/kittyrelay.py

This module connects to that hub and creates KittySploit sessions.
v2 adds E2E ChaCha20-Poly1305 encryption + keepalive over the bridged stream.
"""

from kittysploit import *
import socket

from lib.relay.client import connect_operator


class Module(Listener):

    __info__ = {
        "name": "P2P Relay Listener",
        "description": (
            "Operator listener for NAT-friendly C2 via KittyRelay hub (v2 E2E encrypted). "
            "Start the hub with the standalone command: kittyrelay (no framework). "
            "Agents use p2p relay payloads; operators use this module (role=operator)."
        ),
        "author": "KittySploit Team",
        "version": "2.0.0",
        "handler": Handler.REVERSE,
        "session_type": SessionType.SHELL,
        "references": [
            "https://github.com/Kittysploit/Kittysploit-framework",
        ],
    }

    role = OptChoice(
        "operator",
        "Role: operator (receive sessions) or agent (local smoke test). "
        "Hub: run standalone `kittyrelay` instead of this module.",
        True,
        choices=["operator", "agent"],
    )
    lhost = OptString("0.0.0.0", "Bind/listen address (relay) or local label", False)
    lport = OptPort(9000, "Relay port (relay bind / operator connect)", True)
    relay_host = OptString("127.0.0.1", "Relay hub address (operator/agent roles)", False)
    relay_port = OptPort(9000, "Relay hub port (operator/agent roles)", False)
    relay_token = OptString("kitty-room", "Shared room token pairing agents and operators", True)
    relay_psk = OptString("", "Pre-shared secret for E2E key (must match payload)", False, True)
    encrypt = OptBool(True, "E2E encrypt relay stream (ChaCha20-Poly1305)", False, True)
    keepalive_interval = OptInteger(30, "Encrypted keepalive interval in seconds (0=off)", False, True)
    alert_on_disconnect = OptBool(True, "Alert when relay agent disconnects", False, True)

    def run(self):
        role = str(self.role).lower()
        if role == "operator":
            return self._run_operator()
        if role == "agent":
            return self._run_agent_test()
        print_error(f"Unknown role: {role}")
        return False

    def _disconnect_alert(self, token: str) -> None:
        if not bool(self.alert_on_disconnect):
            return
        print_warning(f"Relay agent disconnected (room: {token})")

    def _run_operator(self):
        relay_host = str(self.relay_host or self.lhost or "127.0.0.1")
        relay_port = int(self.relay_port or self.lport)
        token = str(self.relay_token)
        psk = str(self.relay_psk or "")
        keepalive = int(self.keepalive_interval or 0)
        encrypt = bool(self.encrypt)

        try:
            print_info("Hub not running? Start: kittyrelay --host 0.0.0.0 --port <port>")
            print_status(f"Connecting to relay {relay_host}:{relay_port} (room: {token})")
            if encrypt:
                print_status("E2E encryption enabled (KSRL v2 / KSF1 frames)")
            print_status("Waiting for an agent on the same token...")

            client_sock = connect_operator(
                relay_host,
                relay_port,
                token,
                timeout=120.0,
                encrypt=encrypt,
                psk=psk,
                keepalive_interval=keepalive,
                keepalive_timeout=max(90.0, keepalive * 3 if keepalive > 0 else 90.0),
                on_disconnect=lambda: self._disconnect_alert(token),
            )

            pub = str(getattr(self, "session_implant_public_key", "") or "").strip()
            implant_id = token
            if pub:
                try:
                    from core.framework.connection_watchdog import read_identity_hello

                    verified_id, client_sock = read_identity_hello(client_sock, pub, timeout=3.0)
                    if verified_id:
                        implant_id = verified_id
                        print_success(f"Verified implant identity: {implant_id}")
                    else:
                        print_warning("No KSID hello received from agent")
                except Exception as exc:
                    print_warning(f"Implant identity verification failed: {exc}")

            peer = client_sock.getpeername()
            print_success(f"Paired with agent via relay ({peer[0]}:{peer[1]})")
            return (
                client_sock,
                relay_host,
                relay_port,
                {
                    "connection_type": "p2p_relay",
                    "protocol": "tcp",
                    "relay_token": token,
                    "implant_id": implant_id,
                    "relay_endpoint": f"{relay_host}:{relay_port}",
                    "relay_encrypted": encrypt,
                    "pty_mode": True,
                },
            )
        except socket.timeout:
            print_warning("Timed out waiting for agent on relay")
            return None
        except OSError as exc:
            if not self.stop_flag.is_set():
                print_error(f"Operator relay error: {exc}")
            return None

    def _run_agent_test(self):
        """Local smoke-test: connect as agent without spawning a shell."""
        relay_host = str(self.relay_host or self.lhost or "127.0.0.1")
        relay_port = int(self.relay_port or self.lport)
        token = str(self.relay_token)
        try:
            from lib.relay.client import connect_agent

            sock = connect_agent(
                relay_host,
                relay_port,
                token,
                encrypt=bool(self.encrypt),
                psk=str(self.relay_psk or ""),
                keepalive_interval=int(self.keepalive_interval or 0),
            )
            print_success(f"Agent registered on relay room '{token}' (test mode, no shell)")
            print_info("Use role=operator on another console to complete pairing")
            sock.settimeout(1.0)
            try:
                while not self.stop_flag.is_set():
                    data = sock.recv(4096)
                    if not data:
                        break
                    sock.sendall(data)
            except socket.timeout:
                return None
            return False
        except OSError as exc:
            print_error(f"Agent test error: {exc}")
            return False

    def shutdown(self):
        pass
