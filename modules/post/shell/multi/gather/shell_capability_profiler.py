from kittysploit import *


class Module(Post):
    __info__ = {
        "name": "Shell Capability Profiler",
        "description": "Fingerprint an unusual shell and list available interpreters, transfer tools, TTY support, and execution constraints",
        "platform": Platform.MULTI,
        "author": "KittySploit Team",
        "session_type": [
            SessionType.SHELL,
            SessionType.METERPRETER,
            SessionType.SSH,
            SessionType.PHP,
            SessionType.PYTHON,
        ],
    'agent': {
        'risk': 'intrusive',
        'effects': ['active_exploitation'],
        'expected_requests': 2,
        'reversible': False,
        'approval_required': True,
        'produces': ['risk_signals'],
        'cost': 1.5,
        'noise': 0.5,
        'value': 1.0,
        'requires':         {'min_endpoints': 0,
         'min_params': 0,
         'tech_hints_any': [],
         'tech_hints_all': [],
         'specializations_any': [],
         'risk_signals_any': [],
         'auth_session': False,
         'capabilities_any': [],
         'capabilities_all': [],
         'confidence_min': {},
         'confidence_min_any': {},
         'endpoint_pattern_any': [],
         'param_any': [],
         'api_surface_ready': False},
        'chain':         {'produces_capabilities': [{'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 's7comm', 'from_detail': ''},
                                   {'capability': 'ot_assets', 'from_detail': ''},
                                   {'capability': 'ot_assets', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''}],
         'consumes_capabilities': [],
         'option_bindings': {},
         'suggested_followups': []},
    },
    }

    target = OptChoice("auto", "Target platform: auto, unix, windows", False, choices=["auto", "unix", "windows"])
    timeout_safe = OptBool(True, "Prefer short commands that should not block fragile shells", False)

    UNIX_COMMANDS = (
        ("identity", "id 2>/dev/null; whoami 2>/dev/null"),
        ("kernel", "uname -a 2>/dev/null"),
        ("shell", "printf 'SHELL=%s\\nPATH=%s\\nTERM=%s\\n' \"$SHELL\" \"$PATH\" \"$TERM\" 2>/dev/null"),
        ("tty", "tty 2>/dev/null || printf 'no tty\\n'"),
        ("pwd", "pwd 2>/dev/null"),
        ("writable tmp", "for d in /dev/shm /tmp /var/tmp .; do [ -w \"$d\" ] && printf '%s\\n' \"$d\"; done 2>/dev/null"),
        ("interpreters", "for c in sh bash dash ash zsh ksh python3 python perl ruby php node lua busybox socat nc ncat curl wget openssl base64; do command -v \"$c\" 2>/dev/null; done"),
        ("container hints", "cat /proc/1/cgroup 2>/dev/null | head -n 5; test -f /.dockerenv && echo /.dockerenv"),
        ("limits", "ulimit -a 2>/dev/null | head -n 20"),
    )

    WINDOWS_COMMANDS = (
        ("identity", "whoami & hostname"),
        ("system", "ver"),
        ("shell", "echo COMSPEC=%COMSPEC% & echo PATH=%PATH%"),
        ("pwd", "cd"),
        ("interpreters", "where powershell 2>NUL & where pwsh 2>NUL & where python 2>NUL & where py 2>NUL & where certutil 2>NUL & where bitsadmin 2>NUL & where curl 2>NUL & where nc 2>NUL & where ncat 2>NUL"),
        ("integrity", "whoami /groups | findstr /i \"Mandatory\""),
        ("privileges", "whoami /priv"),
    )

    def run(self):
        platform = self._detect_platform()
        print_info("=" * 80)
        print_status("Shell capability profiler")
        print_info(f"Profile: {platform}")

        commands = self.WINDOWS_COMMANDS if platform == "windows" else self.UNIX_COMMANDS
        results = {}
        for label, command in commands:
            output = self._run_cmd(command)
            results[label] = output
            self._print_block(label, output)

        print_info("-" * 80)
        print_status("Recommended next moves")
        for hint in self._build_hints(platform, results):
            print_info(f"  - {hint}")

        print_info("=" * 80)
        print_success("Shell capability profiling completed")
        return True

    def _run_cmd(self, command: str) -> str:
        if bool(self.timeout_safe):
            command = self._wrap_timeout(command)
        try:
            output = self.cmd_execute(command)
            return output.strip() if output else ""
        except Exception as exc:
            return f"(command failed: {exc})"

    def _wrap_timeout(self, command: str) -> str:
        target = str(self.target or "auto").lower()
        if target == "windows":
            return command
        return f"({command}) 2>&1"

    def _detect_platform(self) -> str:
        selected = str(self.target or "auto").strip().lower()
        if selected == "windows":
            return "windows"
        if selected == "unix":
            return "unix"

        unix_probe = self._plain_cmd("uname -s 2>/dev/null")
        if unix_probe:
            return "unix"
        win_probe = self._plain_cmd("cmd /c ver")
        if "windows" in win_probe.lower():
            return "windows"
        return "unix"

    def _plain_cmd(self, command: str) -> str:
        try:
            output = self.cmd_execute(command)
            return output.strip() if output else ""
        except Exception:
            return ""

    def _print_block(self, label: str, output: str):
        print_info("-" * 80)
        print_status(label)
        if output:
            for line in output.splitlines()[:40]:
                print_info(f"  {line}")
        else:
            print_info("  (no output)")

    def _build_hints(self, platform: str, results: dict) -> list:
        joined = "\n".join(results.values()).lower()
        hints = []
        if platform == "unix":
            if "python3" in joined or "/python" in joined:
                hints.append("Python is available; PTY upgrade and structured collectors are likely viable.")
            if "busybox" in joined:
                hints.append("BusyBox detected; prefer POSIX sh syntax and BusyBox applets for minimal systems.")
            if "no tty" in joined:
                hints.append("No TTY reported; avoid interactive sudo/su flows unless you first upgrade the shell.")
            if "/dev/shm" in joined or "/tmp" in joined:
                hints.append("Writable temp path found; staged tooling can use that directory if approved.")
        else:
            if "powershell" in joined or "pwsh" in joined:
                hints.append("PowerShell is available; use PowerShell-native post modules for richer collection.")
            if "mandatory" in joined:
                hints.append("Integrity data is available; review it before attempting privileged actions.")
        if not hints:
            hints.append("Capabilities are sparse; keep commands short, POSIX/cmd-compatible, and verify each assumption.")
        return hints
