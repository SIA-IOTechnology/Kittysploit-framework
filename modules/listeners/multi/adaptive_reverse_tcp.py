#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Adaptive reverse TCP listener.

Detects OS on connect, attempts Unix PTY upgrade, stamps session metadata so
classic_shell / post modules can target the right platform.
"""

from kittysploit import *
import socket

from lib.shell.adaptive_upgrade import adapt_connection


class Module(Listener):

    __info__ = {
        "name": "Adaptive Reverse TCP Listener",
        "description": (
            "Reverse TCP listener that probes OS on connect and auto-upgrades "
            "Unix shells to PTY. Windows stays in line mode."
        ),
        "author": "KittySploit Team",
        "handler": Handler.REVERSE,
        "session_type": SessionType.SHELL,
    }

    lhost = OptString("0.0.0.0", "Local IPv4 or IPv6 address", True)
    lport = OptPort(4444, "Local port", True)
    auto_upgrade = OptBool(
        True,
        "Attempt in-band Unix PTY upgrade after OS detection",
        False,
    )
    probe_timeout = OptInteger(
        2,
        "Seconds to wait for each OS probe command",
        False,
        True,
    )
    upgrade_timeout = OptInteger(
        3,
        "Seconds budget for PTY upgrade probes",
        False,
        True,
    )

    def run(self, background=False):
        """Accept one connection, adapt it, return session tuple for the framework loop.

        In background mode, start the Listener accept thread and return immediately.
        """
        if background:
            # Listener.start() runs _run_listener → run() in a daemon thread
            return self.start()

        try:
            if not hasattr(self, "sock") or self.sock is None:
                print_status(f"Starting adaptive listener on {self.lhost}:{self.lport}")
                print_status("Waiting for reverse shells (OS probe + optional PTY upgrade)...")
                print_status("Press Ctrl+C to stop the listener")

                self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                self.sock.settimeout(1.0)
                self.sock.bind((self.lhost, int(self.lport)))
                self.sock.listen(5)
                print_success(f"Adaptive listening on {self.lhost}:{self.lport}")

            try:
                client_socket, address = self.sock.accept()
                print_success(f"Connection received from {address[0]}:{address[1]}")

                try:
                    client_socket.settimeout(None)
                except Exception:
                    pass

                try:
                    stamp, caps = adapt_connection(
                        client_socket,
                        auto_upgrade=bool(self.auto_upgrade),
                        probe_timeout=float(self.probe_timeout or 2),
                        upgrade_timeout=float(self.upgrade_timeout or 3),
                    )
                except Exception as exc:
                    print_warning(f"Adaptive probe failed ({exc}); falling back to line mode")
                    stamp = {
                        "connection_type": "reverse",
                        "protocol": "tcp",
                        "adaptive": True,
                        "stager_line_mode": True,
                        "pty_mode": False,
                    }
                    caps = {"platform": "unknown", "pty_upgraded": False, "error": str(exc)}

                platform = caps.get("platform") or stamp.get("platform") or "unknown"
                pty_ok = bool(caps.get("pty_upgraded") or stamp.get("pty_mode"))
                print_info(
                    f"Adaptive: platform={platform} "
                    f"pty={'yes' if pty_ok else 'no'} "
                    f"probe={caps.get('probe_method') or '-'} "
                    f"upgrade={caps.get('upgrade_method') or '-'}"
                )

                # Help listener.py merge platform / pty into session creation path
                if stamp.get("platform"):
                    self.session_platform = str(stamp["platform"])
                self.session_pty_mode = bool(stamp.get("pty_mode"))

                return (client_socket, address[0], address[1], stamp)

            except socket.timeout:
                return None
            except KeyboardInterrupt:
                print_info("Interrupted by user")
                return False
            except Exception as e:
                if not self.stop_flag.is_set():
                    print_error(f"Error accepting connection: {e}")
                    return None
                return False

        except KeyboardInterrupt:
            print_info("Interrupted by user")
            return False
        except OSError as e:
            print_error(f"Listener error: {e}")
            return False

    def shutdown(self):
        try:
            if hasattr(self, "sock") and self.sock:
                try:
                    self.sock.close()
                except OSError:
                    pass
                self.sock = None
        except OSError:
            pass
        self.running = False
