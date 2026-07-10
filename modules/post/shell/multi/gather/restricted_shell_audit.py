from kittysploit import *

import re


class Module(Post):
    __info__ = {
        "name": "Restricted Shell Audit",
        "description": "Identify restricted or atypical shell constraints, escape-capable binaries, sudo posture, and writable PATH risks",
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
    include_sudo = OptBool(True, "Run non-interactive sudo -n -l on Unix targets", False)
    max_lines = OptInteger(80, "Maximum lines per section", False)

    ESCAPE_BINARIES = (
        "vi",
        "vim",
        "less",
        "more",
        "man",
        "find",
        "awk",
        "sed",
        "tar",
        "zip",
        "python3",
        "python",
        "perl",
        "ruby",
        "lua",
        "node",
        "nmap",
        "socat",
        "ssh",
        "scp",
        "rsync",
        "busybox",
    )

    def run(self):
        platform = self._detect_platform()
        print_info("=" * 80)
        print_status("Restricted shell audit")
        print_info(f"Profile: {platform}")

        if platform == "windows":
            self._windows_audit()
        else:
            self._unix_audit()

        print_info("=" * 80)
        print_success("Restricted shell audit completed")
        return True

    def _unix_audit(self):
        self._section("Shell identity", self._run("printf 'SHELL=%s\\n0=%s\\nPATH=%s\\n' \"$SHELL\" \"$0\" \"$PATH\"; id; tty 2>/dev/null || true"))
        self._section("Restriction indicators", self._run("set -o 2>/dev/null | grep -Ei 'restricted|monitor|privileged' || true; echo \"$-\""))
        self._section("Escape-capable binaries in PATH", self._find_unix_binaries())
        self._section("Writable PATH directories", self._run("IFS=:; for d in $PATH; do [ -n \"$d\" ] && [ -w \"$d\" ] && printf '%s\\n' \"$d\"; done 2>/dev/null"))
        self._section("Writable startup files", self._run("for f in ~/.profile ~/.bashrc ~/.bash_profile ~/.zshrc ~/.ssh/authorized_keys; do [ -e \"$f\" ] && [ -w \"$f\" ] && printf '%s\\n' \"$f\"; done 2>/dev/null"))
        if bool(self.include_sudo):
            self._section("sudo non-interactive listing", self._run("sudo -n -l 2>&1"))

        hints = self._unix_hints()
        self._section("Interpretation", "\n".join(hints))

    def _windows_audit(self):
        self._section("Shell identity", self._run("whoami & echo COMSPEC=%COMSPEC% & echo PATH=%PATH%"))
        self._section("Constrained language / policy", self._run('powershell -NoP -Command "$ExecutionContext.SessionState.LanguageMode; Get-ExecutionPolicy -List" 2>NUL'))
        self._section("Useful binaries in PATH", self._run("where powershell 2>NUL & where pwsh 2>NUL & where cmd 2>NUL & where wscript 2>NUL & where cscript 2>NUL & where mshta 2>NUL & where rundll32 2>NUL & where regsvr32 2>NUL & where certutil 2>NUL & where bitsadmin 2>NUL & where curl 2>NUL"))
        self._section("Writable user startup locations", self._run('powershell -NoP -Command "$p=@($env:APPDATA+\'\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\', $env:TEMP); foreach($x in $p){ if(Test-Path $x){ try{ $acl=Get-Acl $x; Write-Output $x }catch{} } }" 2>NUL'))
        self._section("Privileges", self._run("whoami /priv"))

    def _find_unix_binaries(self) -> str:
        names = " ".join(self.ESCAPE_BINARIES)
        return self._run(f"for c in {names}; do command -v \"$c\" 2>/dev/null; done")

    def _unix_hints(self) -> list:
        hints = []
        shell = self._run("printf '%s' \"$SHELL\" 2>/dev/null")
        if re.search(r"r(bash|sh|ksh|zsh)$", shell or ""):
            hints.append("Restricted shell name detected; prefer allowed binaries and avoid assuming cd, slash paths, or redirection work.")
        tty = self._run("tty 2>/dev/null")
        if "not a tty" in tty.lower() or not tty:
            hints.append("No interactive TTY confirmed; use non-interactive checks and upgrade only with operator approval.")
        writable_path = self._run("IFS=:; for d in $PATH; do [ -n \"$d\" ] && [ -w \"$d\" ] && printf '%s\\n' \"$d\"; done 2>/dev/null")
        if writable_path:
            hints.append("Writable PATH directory found; this is a privilege-escalation risk if privileged scripts call bare command names.")
        if not hints:
            hints.append("No obvious restriction or writable PATH issue found with these lightweight checks.")
        return hints

    def _detect_platform(self) -> str:
        selected = str(self.target or "auto").strip().lower()
        if selected == "windows":
            return "windows"
        if selected == "unix":
            return "unix"
        if self._run("uname -s 2>/dev/null"):
            return "unix"
        if "windows" in self._run("cmd /c ver").lower():
            return "windows"
        return "unix"

    def _run(self, command: str) -> str:
        try:
            output = self.cmd_execute(command)
            return output.strip() if output else ""
        except Exception as exc:
            return f"(command failed: {exc})"

    def _section(self, title: str, output: str):
        print_info("-" * 80)
        print_status(title)
        if not output:
            print_info("  (no output)")
            return
        for line in output.splitlines()[: max(1, int(self.max_lines))]:
            print_info(f"  {line}")
