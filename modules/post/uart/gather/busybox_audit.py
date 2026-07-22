#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
UART BusyBox Audit - Enumerates BusyBox applets and flags risky ones over UART
"""

from kittysploit import *
from lib.protocols.hardware.uart_session_mixin import UartSessionMixin
import json
from datetime import datetime
import re


# Applets often useful for foothold / persistence / data exfil on embedded targets
RISKY_APPLETS = {
    "ash",
    "sh",
    "hush",
    "bash",
    "telnetd",
    "httpd",
    "ftpd",
    "tcpsvd",
    "udpsvd",
    "nc",
    "netcat",
    "wget",
    "curl",
    "tftp",
    "ftpget",
    "ftpput",
    "ssh",
    "dropbear",
    "scp",
    "nmap",
    "chpasswd",
    "passwd",
    "su",
    "sudo",
    "login",
    "getty",
    "init",
    "reboot",
    "halt",
    "poweroff",
    "insmod",
    "rmmod",
    "modprobe",
    "mount",
    "umount",
    "dd",
    "hexdump",
    "xxd",
    "iptables",
    "ip",
    "ifconfig",
    "route",
    "crontab",
    "kill",
    "killall",
    "find",
    "chmod",
    "chown",
}

PROBE_COMMANDS = [
    "busybox",
    "busybox --help",
    "busybox --list",
    "ls -l `which busybox` 2>/dev/null",
    "type busybox 2>/dev/null; which busybox 2>/dev/null",
]


class Module(Post, UartSessionMixin):
    __info__ = {
        "name": "UART BusyBox Audit",
        "description": (
            "Audits BusyBox on an embedded UART console: detects presence, "
            "enumerates applets, and highlights risky networking / shell tools"
        ),
        "author": "KittySploit Team",
        "version": "1.0.0",
        "session_type": SessionType.UART,
        "tags": ["hardware", "uart", "gather", "busybox", "embedded", "audit"],
        "references": [
            "https://busybox.net/",
            "https://attack.mitre.org/techniques/T0842/",
        ],
        "agent": {
            "risk": "intrusive",
            "effects": ["recon"],
            "expected_requests": 5,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals"],
            "cost": 0.8,
            "noise": 0.25,
            "value": 1.5,
            "chain": {
                "consumes_capabilities": ["uart_session"],
                "produces_capabilities": [
                    {"capability": "busybox_inventory", "from_detail": "busybox_audit"},
                ],
                "suggested_followups": [
                    "post/uart/gather/firmware_info",
                    "post/uart/manage/send_break",
                ],
            },
        },
    }

    wait = OptFloat(1.5, "Seconds to wait per probe command", required=True)
    newline = OptString("\\r\\n", "Newline sequence", required=False)
    output_file = OptString("", "Optional JSON output file", required=False)
    store_results = OptBool(True, "Store results in session.data['busybox_audit']", required=False)

    def check(self):
        sid = str(self.session_id or "").strip()
        if not sid:
            print_error("Session ID not set")
            return False
        session = self.framework.session_manager.get_session(sid) if self.framework else None
        if not session:
            print_error("Session not found")
            return False
        if str(session.session_type).lower() != SessionType.UART.value:
            print_error(f"Session is not UART (type: {session.session_type})")
            return False
        try:
            self.open_uart()
            return True
        except Exception as exc:
            print_error(str(exc))
            return False

    def _newline(self) -> str:
        raw = str(self.newline or "\\r\\n")
        return raw.encode("utf-8").decode("unicode_escape")

    def run(self):
        client = self.open_uart()
        wait = max(0.3, float(self.wait or 1.5))
        newline = self._newline()
        info = client.connection_summary()

        print_info("=" * 80)
        print_success("UART BusyBox Audit")
        print_info(f"Device : {info.get('port')} @ {info.get('baudrate')}")
        print_info("=" * 80)

        probes = []
        combined = []
        for cmd in PROBE_COMMANDS:
            print_status(f"$ {cmd}")
            exchange = client.exchange(cmd, wait=wait, newline=newline)
            probes.append(
                {
                    "command": cmd,
                    "success": exchange.success,
                    "response": exchange.text,
                    "error": exchange.error,
                }
            )
            if exchange.success and exchange.text:
                combined.append(exchange.text)
                preview = exchange.text.strip()
                if preview:
                    print_info(preview if len(preview) < 600 else preview[:600] + "...")

        blob = "\n".join(combined)
        present = bool(re.search(r"BusyBox\s+v?\d", blob, re.I)) or "busybox" in blob.lower()
        version = None
        m = re.search(r"BusyBox\s+v?([0-9]+(?:\.[0-9]+)+[^\s,]*)", blob, re.I)
        if m:
            version = m.group(1)
            present = True

        applets = self._parse_applets(blob)
        risky = sorted(a for a in applets if a.lower() in RISKY_APPLETS)

        report = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "device": info.get("port"),
            "baudrate": info.get("baudrate"),
            "busybox_present": present,
            "version": version,
            "applet_count": len(applets),
            "applets": applets,
            "risky_applets": risky,
            "probes": probes,
        }

        print_info("-" * 80)
        if not present and not applets:
            print_warning("BusyBox not clearly detected (no shell, wrong baud, or not installed)")
        else:
            print_success(f"BusyBox {'detected' if present else 'applets parsed'}"
                          + (f" v{version}" if version else ""))
            print_info(f"Applets enumerated : {len(applets)}")
            if applets:
                print_info("Applets: " + ", ".join(applets[:40]) + ("..." if len(applets) > 40 else ""))
            if risky:
                print_warning(f"Risky applets ({len(risky)}): " + ", ".join(risky))
            else:
                print_info("No high-risk applets matched the built-in list")

        if bool(self.store_results):
            session = self._resolve_session()
            if session:
                data = session.data if isinstance(session.data, dict) else {}
                data["busybox_audit"] = report
                session.data = data

        out = str(self.output_file or "").strip()
        if out:
            try:
                with open(out, "w", encoding="utf-8") as handle:
                    json.dump(report, handle, indent=2)
                print_success(f"Wrote report to {out}")
            except OSError as exc:
                print_error(f"Failed to write output: {exc}")

        return True

    def _parse_applets(self, text: str):
        """Extract applet names from busybox --list / help output."""
        found = []
        seen = set()

        # busybox --list often prints one applet per line
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("$") or line.startswith("#"):
                continue
            if re.fullmatch(r"[A-Za-z][A-Za-z0-9_\-+.]*", line):
                key = line.lower()
                if key not in seen and key not in ("busybox", "currently", "defined", "functions"):
                    seen.add(key)
                    found.append(line)
                continue
            # help line: ", applet, applet2," style
            if "," in line and "BusyBox" not in line:
                for token in re.split(r"[\s,]+", line):
                    token = token.strip()
                    if re.fullmatch(r"[A-Za-z][A-Za-z0-9_\-+.]*", token):
                        key = token.lower()
                        if key not in seen and len(token) < 32:
                            seen.add(key)
                            found.append(token)

        # Also catch "Currently defined functions:" blocks
        m = re.search(r"Currently defined functions:\s*(.*)", text, re.I | re.S)
        if m:
            block = m.group(1)
            for token in re.split(r"[\s,]+", block):
                token = token.strip().rstrip(",")
                if re.fullmatch(r"[A-Za-z][A-Za-z0-9_\-+.]*", token):
                    key = token.lower()
                    if key not in seen and len(token) < 32:
                        seen.add(key)
                        found.append(token)

        return sorted(found, key=str.lower)
