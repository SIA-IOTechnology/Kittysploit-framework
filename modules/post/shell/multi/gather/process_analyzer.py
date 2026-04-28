from kittysploit import *
import re


class Module(Post):
    __info__ = {
        "name": "Process Analyzer",
        "description": "Analyze running processes and highlight suspicious execution patterns",
        "platform": Platform.MULTI,
        "author": "KittySploit Team",
        "session_type": [SessionType.SHELL, SessionType.METERPRETER, SessionType.SSH],
    }

    target = OptChoice("auto", "Target platform: auto, linux, windows", False, choices=["auto", "linux", "windows"])
    max_processes = OptInteger(120, "Maximum process lines to inspect", False)
    max_results = OptInteger(40, "Maximum suspicious lines to print", False)

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

    def _detect_platform(self) -> str:
        selected = str(self.target or "auto").strip().lower()
        if selected in ("linux", "windows"):
            return selected
        if self._run_cmd("uname -s 2>/dev/null"):
            return "linux"
        probe = self._run_cmd("cmd /c ver")
        if probe and "windows" in probe.lower():
            return "windows"
        return "linux"

    def _score_line(self, line: str) -> int:
        score = 0
        rules = [
            (r"(base64|frombase64string|encodedcommand|-enc\b)", 3),
            (r"(powershell|pwsh).*(iex|invoke-expression|downloadstring)", 4),
            (r"(curl|wget).*(\||&&).*(sh|bash)", 4),
            (r"(/tmp/|\\temp\\|\\appdata\\local\\temp\\)", 2),
            (r"(nc |ncat|socat|mshta|rundll32|regsvr32|certutil|bitsadmin)", 3),
            (r"(mimikatz|procdump|secretsdump|lsass)", 5),
            (r"(python|perl|php|bash)\s+-c\s+", 2),
        ]
        lowered = line.lower()
        for pattern, weight in rules:
            if re.search(pattern, lowered, re.IGNORECASE):
                score += weight
        return score

    def _analyze(self, lines):
        suspicious = []
        for line in lines:
            score = self._score_line(line)
            if score > 0:
                suspicious.append((score, line))
        suspicious.sort(key=lambda x: x[0], reverse=True)
        return suspicious

    def _collect_linux(self):
        limit = int(self.max_processes)
        output = self._run_cmd("ps auxww 2>/dev/null | head -n {n}".format(n=limit))
        return [line.strip() for line in output.splitlines() if line.strip()]

    def _collect_windows(self):
        limit = int(self.max_processes)
        output = self._run_cmd(
            'powershell -NoP -Command "Get-CimInstance Win32_Process | '
            "Select-Object -First {n} ProcessId,ParentProcessId,Name,CommandLine | "
            'ForEach-Object { \\"$($_.ProcessId)\\t$($_.ParentProcessId)\\t$($_.Name)\\t$($_.CommandLine)\\" }"'.format(n=limit)
        )
        return [line.strip() for line in output.splitlines() if line.strip()]

    def run(self):
        platform = self._detect_platform()
        self._print_section("Process Analyzer")
        print_info(f"Detected platform: {platform}")

        lines = self._collect_windows() if platform == "windows" else self._collect_linux()
        if not lines:
            print_error("No process data returned by target session")
            return False

        suspicious = self._analyze(lines)
        self._print_section("Suspicious Process Patterns")
        if not suspicious:
            print_success("No suspicious process pattern detected with current heuristics")
            return True

        max_results = int(self.max_results)
        for score, line in suspicious[:max_results]:
            if score >= 7:
                print_error(f"[score={score}] {line}")
            elif score >= 4:
                print_warning(f"[score={score}] {line}")
            else:
                print_info(f"[score={score}] {line}")

        self._print_section("Summary")
        print_warning(f"Suspicious process entries: {len(suspicious)}")
        return True
