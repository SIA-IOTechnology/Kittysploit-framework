#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
from lib.post.linux.system import System


class Module(Post, System):
    __info__ = {
        "name": "Linux Persistence Audit",
        "description": "Audit common Linux persistence locations (systemd, cron, startup scripts, shell profiles)",
        "platform": Platform.LINUX,
        "author": "KittySploit Team",
        "session_type": [
            SessionType.SHELL,
            SessionType.METERPRETER,
            SessionType.SSH,
        ],
    }

    max_results = OptInteger(40, "Maximum lines to print per check", False)

    def _print_section(self, title: str):
        print_status("=" * 60)
        print_status(title)
        print_status("=" * 60)

    def _run_cmd(self, command: str) -> str:
        try:
            output = self.cmd_exec(command)
            return output.strip() if output else ""
        except Exception:
            return ""

    def _print_if_any(self, label: str, output: str) -> int:
        if not output:
            print_info(f"{label}: no findings")
            return 0
        print_warning(f"{label}:")
        for line in output.splitlines():
            line = line.strip()
            if line:
                print_info(f"  {line}")
        return 1

    def _audit_systemd(self) -> int:
        self._print_section("Systemd Services and Timers")
        findings = 0
        limit = int(self.max_results)

        findings += self._print_if_any(
            "Enabled service units",
            self._run_cmd(
                "systemctl list-unit-files --type=service --state=enabled --no-pager 2>/dev/null | "
                f"head -n {limit}"
            ),
        )
        findings += self._print_if_any(
            "Enabled timers",
            self._run_cmd(
                "systemctl list-timers --all --no-pager 2>/dev/null | "
                f"head -n {limit}"
            ),
        )
        findings += self._print_if_any(
            "Potential custom service files",
            self._run_cmd(
                "find /etc/systemd/system /usr/lib/systemd/system "
                "-maxdepth 2 -type f \\( -name '*.service' -o -name '*.timer' \\) "
                "2>/dev/null | grep -E '/etc/systemd/system|/multi-user.target.wants/' "
                f"| head -n {limit}"
            ),
        )
        return findings

    def _audit_cron(self) -> int:
        self._print_section("Cron Persistence")
        findings = 0
        limit = int(self.max_results)

        findings += self._print_if_any(
            "System crontab entries",
            self._run_cmd(
                "awk 'NF && $1 !~ /^#/' /etc/crontab 2>/dev/null | "
                f"head -n {limit}"
            ),
        )
        findings += self._print_if_any(
            "Cron.d entries",
            self._run_cmd(
                "find /etc/cron.d -type f 2>/dev/null -exec awk 'NF && $1 !~ /^#/' {} \\; | "
                f"head -n {limit}"
            ),
        )
        findings += self._print_if_any(
            "User crontabs",
            self._run_cmd(
                "for u in $(cut -d: -f1 /etc/passwd 2>/dev/null); do "
                "crontab -u \"$u\" -l 2>/dev/null | awk -v user=\"$u\" 'NF && $1 !~ /^#/ {print user\": \"$0}'; "
                f"done | head -n {limit}"
            ),
        )
        return findings

    def _audit_startup_scripts(self) -> int:
        self._print_section("Startup Scripts and Login Hooks")
        findings = 0
        limit = int(self.max_results)

        findings += self._print_if_any(
            "rc.local content",
            self._run_cmd(
                "awk 'NF && $1 !~ /^#/' /etc/rc.local 2>/dev/null | "
                f"head -n {limit}"
            ),
        )
        findings += self._print_if_any(
            "Global shell profile hooks",
            self._run_cmd(
                "for f in /etc/profile /etc/bash.bashrc /etc/zsh/zshrc; do "
                "[ -f \"$f\" ] && awk -v file=\"$f\" 'NF && $1 !~ /^#/ {print file\": \"$0}' \"$f\"; "
                f"done 2>/dev/null | head -n {limit}"
            ),
        )
        findings += self._print_if_any(
            "User profile startup commands",
            self._run_cmd(
                "find /home /root -maxdepth 2 -type f "
                "\\( -name '.bashrc' -o -name '.profile' -o -name '.zshrc' \\) "
                "2>/dev/null | while read -r f; do "
                "awk -v file=\"$f\" 'NF && $1 !~ /^#/ {print file\": \"$0}' \"$f\"; done | "
                f"head -n {limit}"
            ),
        )
        findings += self._print_if_any(
            "XDG autostart entries",
            self._run_cmd(
                "find /etc/xdg/autostart /home/*/.config/autostart "
                "-maxdepth 1 -type f -name '*.desktop' 2>/dev/null | "
                f"head -n {limit}"
            ),
        )
        return findings

    def run(self):
        print_status("Starting Linux persistence audit...")
        findings = 0
        findings += self._audit_systemd()
        findings += self._audit_cron()
        findings += self._audit_startup_scripts()

        if findings == 0:
            print_success("Audit completed: no obvious persistence artifacts were detected in audited paths")
        else:
            print_success(f"Audit completed: {findings} section(s) contain potential persistence artifacts")
        return True
