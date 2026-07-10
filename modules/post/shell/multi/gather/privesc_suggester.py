from kittysploit import *


class Module(Post):
    __info__ = {
        "name": "Privesc Suggester",
        "description": "Combine shell capability profiling with local privilege escalation hints",
        "platform": Platform.MULTI,
        "author": "KittySploit Team",
        "session_type": [
            SessionType.SHELL,
            SessionType.METERPRETER,
            SessionType.SSH,
            SessionType.PHP,
            SessionType.PYTHON,
            SessionType.WINRM,
        ],
        "agent": {
            "risk": "intrusive",
            "effects": ["active_exploitation"],
            "expected_requests": 6,
            "reversible": False,
            "approval_required": True,
            "produces": ["risk_signals"],
            "chain": {
                "consumes_capabilities": ["shell"],
                "produces_capabilities": ["root"],
                "suggested_followups": [
                    "post/shell/linux/gather/suid_sgid_hunt",
                    "post/shell/multi/manage/pivot_autoroute",
                ],
            },
        },
    }

    target = OptChoice("auto", "Target platform: auto, unix, windows", False, choices=["auto", "unix", "windows"])
    include_sudo = OptBool(True, "Include sudo -n -l on Unix targets", False)
    include_services = OptBool(True, "Include Windows service misconfig hints", False)

    UNIX_CHECKS = (
        ("identity", "id 2>/dev/null; groups 2>/dev/null"),
        ("kernel", "uname -sr 2>/dev/null"),
        ("capabilities", "command -v getcap >/dev/null 2>&1 && getcap -r / 2>/dev/null | head -n 40"),
        ("suid sample", "find / -xdev -perm -4000 -type f 2>/dev/null | head -n 40"),
        ("writable paths", "find /etc /usr/local/bin /usr/lib /opt -writable -type f 2>/dev/null | head -n 30"),
        ("cron writable", "find /etc/cron* /var/spool/cron -writable 2>/dev/null | head -n 20"),
        ("docker group", "getent group docker 2>/dev/null; test -S /var/run/docker.sock && ls -l /var/run/docker.sock"),
        ("interpreters", "for c in python3 python perl ruby gcc make nmap vim find awk sed; do command -v $c 2>/dev/null; done"),
    )

    WINDOWS_CHECKS = (
        ("identity", "whoami /all"),
        ("privileges", "whoami /priv"),
        ("groups", "whoami /groups"),
        ("always install", "reg query HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated 2>nul & reg query HKCU\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated 2>nul"),
        ("unquoted services", 'wmic service get name,pathname,startmode 2>nul | findstr /i /v "C:\\Windows"'),
        ("autologon", "reg query \"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\" /v DefaultUserName 2>nul"),
        ("stored creds", "cmdkey /list 2>nul"),
    )

    def run(self):
        platform = self._detect_platform()
        print_info("=" * 80)
        print_status("Privesc suggester")
        print_info(f"Platform: {platform}")

        checks = self.WINDOWS_CHECKS if platform == "windows" else self.UNIX_CHECKS
        collected = {}
        for label, command in checks:
            if label == "capabilities" and platform == "unix" and not self._cmd("command -v getcap >/dev/null 2>&1 && echo yes"):
                continue
            output = self._cmd(command)
            collected[label] = output
            self._print_block(label, output)

        if platform == "unix" and self.include_sudo:
            sudo_out = self._cmd("sudo -n -l 2>/dev/null")
            collected["sudo"] = sudo_out
            self._print_block("sudo -l", sudo_out)

        suggestions = self._suggest(platform, collected)
        print_info("-" * 80)
        print_status("Suggested privesc paths")
        if not suggestions:
            print_info("  (no high-confidence paths detected — review raw output above)")
        else:
            for item in suggestions:
                severity = item.get("severity", "info").upper()
                print_info(f"  [{severity}] {item['title']}")
                print_info(f"           {item['detail']}")

        print_info("=" * 80)
        print_success("Privesc suggestion pass completed")
        return True

    def _cmd(self, command: str) -> str:
        try:
            output = self.cmd_execute(command)
            return output.strip() if output else ""
        except Exception as exc:
            return f"(failed: {exc})"

    def _detect_platform(self) -> str:
        selected = str(self.target or "auto").strip().lower()
        if selected in ("unix", "windows"):
            return selected
        if self._cmd("uname -s 2>/dev/null"):
            return "unix"
        if "windows" in self._cmd("cmd /c ver").lower():
            return "windows"
        return "unix"

    def _print_block(self, label: str, output: str):
        print_info("-" * 80)
        print_status(label)
        if output:
            for line in output.splitlines()[:35]:
                print_info(f"  {line}")
        else:
            print_info("  (no output)")

    def _suggest(self, platform: str, data: dict) -> list:
        joined = "\n".join(data.values()).lower()
        out = []

        if platform == "unix":
            if "uid=0" in joined or "root" in data.get("identity", "").splitlines()[0].lower():
                out.append({"severity": "info", "title": "Already root", "detail": "Current identity appears privileged."})
            if "(root)" in data.get("sudo", "").lower() or "nopasswd" in joined:
                out.append({"severity": "high", "title": "Sudo misconfiguration", "detail": "Review sudo -l output for NOPASSWD or broad command allowances."})
            if "/docker.sock" in joined or "docker:" in joined:
                out.append({"severity": "high", "title": "Docker socket / group access", "detail": "Docker membership or socket access may allow host escape / root."})
            if data.get("capabilities"):
                out.append({"severity": "medium", "title": "File capabilities present", "detail": "Inspect getcap output for cap_setuid, cap_sys_admin, cap_dac_override."})
            if data.get("suid sample"):
                out.append({"severity": "medium", "title": "SUID binaries found", "detail": "Run post/shell/linux/gather/suid_sgid_hunt for GTFOBins matching."})
            if data.get("cron writable"):
                out.append({"severity": "high", "title": "Writable cron paths", "detail": "Writable cron directories or scripts can lead to root execution."})
            if any(x in joined for x in ("python3", "python", "gcc", "make")):
                out.append({"severity": "low", "title": "Build/runtime tooling available", "detail": "Compilers or interpreters may support custom exploit staging."})
            if "nt authority\\system" not in joined and "uid=0" not in joined:
                if "4.4" in data.get("kernel", "") or "5." in data.get("kernel", ""):
                    out.append({"severity": "low", "title": "Kernel version collected", "detail": "Cross-check kernel against known public LPEs for this distro."})
        else:
            privs = data.get("privileges", "").lower()
            if "impersonate" in privs or "assignprimarytoken" in privs:
                out.append({"severity": "high", "title": "Token impersonation privileges", "detail": "SeImpersonate/SeAssignPrimaryToken — try post/shell/windows/manage/token_impersonation."})
            if "debug" in privs:
                out.append({"severity": "medium", "title": "SeDebugPrivilege", "detail": "Process memory access may enable credential or token theft."})
            if "alwaysinstallElevated" in joined.replace(" ", "") or "0x1" in data.get("always install", ""):
                out.append({"severity": "high", "title": "AlwaysInstallElevated", "detail": "MSI packages may install with elevated privileges."})
            if self.include_services and data.get("unquoted services"):
                bad = [line for line in data["unquoted services"].splitlines() if " " in line and ".exe" in line.lower()]
                if bad:
                    out.append({"severity": "medium", "title": "Unquoted service paths", "detail": "Services with spaces in unquoted paths may be hijackable."})
            if "mandatory label\\high mandatory level" in joined:
                out.append({"severity": "info", "title": "High integrity session", "detail": "Already elevated relative to medium integrity users."})
            elif "mandatory label\\medium mandatory level" in joined:
                out.append({"severity": "low", "title": "Medium integrity", "detail": "Review UAC bypass modules if admin membership is present."})
            if data.get("stored creds") and "target=" in joined:
                out.append({"severity": "medium", "title": "Stored credentials", "detail": "cmdkey entries may be reusable for lateral movement."})

        if "no tty" in joined or "restricted" in joined:
            out.append({"severity": "low", "title": "Constrained shell", "detail": "Review post/shell/multi/gather/restricted_shell_audit and shell_capability_profiler."})

        return out
