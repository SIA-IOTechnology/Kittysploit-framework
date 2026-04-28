#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
import re


class Module(Post):
    __info__ = {
        "name": "Command History Analyzer",
        "description": "Analyze shell history for suspicious command patterns and incident-response indicators",
        "platform": Platform.MULTI,
        "author": "KittySploit Team",
        "session_type": [
            SessionType.SHELL,
            SessionType.METERPRETER,
            SessionType.SSH,
        ],
    }

    target = OptChoice(
        "auto",
        "Target platform: auto, linux, windows",
        False,
        choices=["auto", "linux", "windows"],
    )
    max_history_files = OptInteger(25, "Maximum history files to inspect", False)
    max_hits_per_category = OptInteger(20, "Maximum suspicious commands to print per category", False)

    _PATTERNS = {
        "defense_evasion": [
            r"\b(history\s+-c|unset\s+HISTFILE|Set-PSReadLineOption\s+-HistorySaveStyle\s+SaveNothing)\b",
            r"\b(clear-eventlog|wevtutil\s+cl|auditpol\s+/clear)\b",
            r"\b(systemctl\s+stop\s+(auditd|rsyslog)|service\s+(auditd|rsyslog)\s+stop)\b",
            r"\b(iptables\s+-F|ufw\s+disable|netsh\s+advfirewall\s+set\s+allprofiles\s+state\s+off)\b",
        ],
        "download_execution": [
            r"\b(curl|wget)\b.*(\|\s*(sh|bash)|-o\s+/tmp|Invoke-WebRequest|iwr)",
            r"\b(powershell(\.exe)?\s+.*(DownloadString|IEX|Invoke-Expression))\b",
            r"\b(certutil\s+-urlcache\s+-f|bitsadmin\s+/transfer|mshta\s+http)\b",
            r"\b(chmod\s+\+x\s+/tmp/|/tmp/[^ ]+\s*$)\b",
        ],
        "credential_access": [
            r"\b(cat|grep|awk)\b.*(/etc/shadow|/etc/passwd|id_rsa|\.aws/credentials|\.kube/config)\b",
            r"\b(secretsdump|mimikatz|lsass|sam\s+save|reg\s+save\s+hklm\\sam)\b",
            r"\b(findstr|grep)\b.*(password|passwd|token|secret|api[_-]?key)\b",
        ],
        "privilege_escalation": [
            r"\b(sudo\s+-l|sudo\s+su|su\s+-|pkexec|doas)\b",
            r"\b(chmod\s+u\+s|setcap\s+|getcap\s+)\b",
            r"\b(useradd|usermod|net\s+user\s+.*\s+/add|net\s+localgroup\s+administrators)\b",
        ],
        "persistence": [
            r"\b(crontab\s+-e|echo\s+.*\|\s*crontab|/etc/cron\.|schtasks\s+/create)\b",
            r"\b(systemctl\s+enable|ln\s+-s\s+.*systemd|rc\.local|update-rc\.d)\b",
            r"\b(reg\s+add\s+HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run)\b",
            r"\b(authorized_keys|Startup\\|\.bashrc|\.profile|\.zshrc)\b",
        ],
        "reconnaissance": [
            r"\b(whoami|id|uname\s+-a|hostnamectl|systeminfo|ipconfig\s+/all)\b",
            r"\b(ifconfig|ip\s+a|route\s+-n|netstat\s+-an|ss\s+-antup|arp\s+-a)\b",
            r"\b(ps\s+aux|tasklist|wmic\s+process|Get-Process)\b",
        ],
    }

    def _run_cmd(self, command: str) -> str:
        try:
            output = self.cmd_execute(command)
            return output.strip() if output else ""
        except Exception:
            try:
                output = self.cmd_exec(command)
                return output.strip() if output else ""
            except Exception:
                return ""

    def _detect_platform(self) -> str:
        selected = str(self.target or "auto").strip().lower()
        if selected in ("linux", "windows"):
            return selected

        probe = self._run_cmd("uname -s 2>/dev/null")
        if probe and any(v in probe.lower() for v in ("linux", "darwin", "bsd")):
            return "linux"

        probe = self._run_cmd("cmd /c ver")
        if probe and "windows" in probe.lower():
            return "windows"
        return "linux"

    def _print_section(self, title: str):
        print_status("=" * 60)
        print_status(title)
        print_status("=" * 60)

    def _collect_history_linux(self) -> list:
        max_files = int(self.max_history_files)
        output = self._run_cmd(
            "find /home /root -maxdepth 4 -type f "
            "\\( -name '.bash_history' -o -name '.zsh_history' -o -name '.history' -o -name '.ash_history' \\) "
            "2>/dev/null | head -n {count}".format(count=max_files)
        )
        files = [line.strip() for line in output.splitlines() if line.strip()]
        commands = []
        for path in files:
            lines = self._run_cmd("tail -n 500 '{path}' 2>/dev/null".format(path=path.replace("'", "'\\''")))
            for idx, line in enumerate(lines.splitlines(), 1):
                cmd = line.strip()
                if cmd and not cmd.startswith("#"):
                    commands.append((path, idx, cmd))
        return commands

    def _collect_history_windows(self) -> list:
        max_files = int(self.max_history_files)
        file_list = self._run_cmd(
            'powershell -NoP -Command "Get-ChildItem -Path C:\\Users -Recurse '
            '-Filter ConsoleHost_history.txt -ErrorAction SilentlyContinue | '
            'Select-Object -First {count} -ExpandProperty FullName"'.format(count=max_files)
        )
        files = [line.strip() for line in file_list.splitlines() if line.strip()]
        commands = []
        for path in files:
            ps = (
                'powershell -NoP -Command "$i=0; Get-Content -Path \\"{path}\\" -ErrorAction SilentlyContinue | '
                'Select-Object -Last 500 | ForEach-Object {{ $i++; \\"$i`t$_\\" }}"'
            ).format(path=path.replace('"', '`"'))
            lines = self._run_cmd(ps)
            for line in lines.splitlines():
                if "\t" not in line:
                    continue
                idx_s, cmd = line.split("\t", 1)
                cmd = cmd.strip()
                if cmd and not cmd.startswith("#"):
                    try:
                        idx = int(idx_s.strip())
                    except Exception:
                        idx = 0
                    commands.append((path, idx, cmd))
        return commands

    def _analyze(self, commands: list) -> dict:
        findings = {category: [] for category in self._PATTERNS}
        for path, line_no, cmd in commands:
            for category, patterns in self._PATTERNS.items():
                matched = False
                for pattern in patterns:
                    if re.search(pattern, cmd, re.IGNORECASE):
                        findings[category].append((path, line_no, cmd))
                        matched = True
                        break
                if matched:
                    # A single command can match multiple categories if needed,
                    # but we avoid duplicate entries in same category.
                    continue
        return findings

    def _severity_score(self, findings: dict) -> int:
        weights = {
            "defense_evasion": 5,
            "credential_access": 5,
            "persistence": 4,
            "privilege_escalation": 4,
            "download_execution": 3,
            "reconnaissance": 1,
        }
        score = 0
        for category, entries in findings.items():
            score += len(entries) * weights.get(category, 1)
        return score

    def _severity_label(self, score: int) -> str:
        if score >= 80:
            return "high"
        if score >= 35:
            return "medium"
        if score > 0:
            return "low"
        return "none"

    def _print_findings(self, findings: dict):
        limit = int(self.max_hits_per_category)
        for category in [
            "defense_evasion",
            "credential_access",
            "persistence",
            "privilege_escalation",
            "download_execution",
            "reconnaissance",
        ]:
            entries = findings.get(category, [])
            self._print_section(f"Category: {category} ({len(entries)} hit(s))")
            if not entries:
                print_info("No suspicious command found in this category")
                continue
            for path, line_no, cmd in entries[:limit]:
                print_warning(f"{path}:{line_no} -> {cmd}")

    def run(self):
        platform = self._detect_platform()
        print_status(f"Running command history forensic analysis on: {platform}")

        if platform == "windows":
            commands = self._collect_history_windows()
        else:
            commands = self._collect_history_linux()

        self._print_section("Collection Summary")
        print_info(f"Collected command lines: {len(commands)}")
        if not commands:
            print_warning("No history data collected from the inspected paths")
            return True

        findings = self._analyze(commands)
        score = self._severity_score(findings)
        severity = self._severity_label(score)

        self._print_findings(findings)
        self._print_section("Risk Summary")
        print_info(f"Forensic score: {score}")
        if severity == "high":
            print_error("Severity: high (multiple strong indicators of malicious activity)")
        elif severity == "medium":
            print_warning("Severity: medium (several suspicious commands detected)")
        elif severity == "low":
            print_warning("Severity: low (limited suspicious activity detected)")
        else:
            print_success("Severity: none (no suspicious command pattern detected)")

        print_success("Command history analysis completed")
        return True
