from kittysploit import *
from lib.post.linux.system import System


class Module(Post, System):
    __info__ = {
        "name": "Linux Package Vulnerability Hint",
        "description": "Collect installed package versions and highlight potentially outdated security-sensitive software",
        "platform": Platform.LINUX,
        "author": "KittySploit Team",
        "session_type": [SessionType.SHELL, SessionType.METERPRETER, SessionType.SSH],
    }

    max_results = OptInteger(80, "Maximum package lines to print", False)

    _KEY_PACKAGES = [
        "openssl",
        "openssh",
        "sudo",
        "kernel",
        "linux-image",
        "bash",
        "curl",
        "wget",
        "python",
        "nginx",
        "apache2",
        "httpd",
        "docker",
        "containerd",
    ]

    def _run_cmd(self, command: str) -> str:
        try:
            output = self.cmd_exec(command)
            return output.strip() if output else ""
        except Exception:
            return ""

    def _print_section(self, title: str):
        print_status("=" * 60)
        print_status(title)
        print_status("=" * 60)

    def _detect_pkg_manager(self) -> str:
        if self.command_exists("dpkg-query"):
            return "dpkg"
        if self.command_exists("rpm"):
            return "rpm"
        if self.command_exists("apk"):
            return "apk"
        return ""

    def _collect_dpkg(self):
        return self._run_cmd("dpkg-query -W -f='${Package}\t${Version}\n' 2>/dev/null")

    def _collect_rpm(self):
        return self._run_cmd("rpm -qa --qf '%{NAME}\t%{VERSION}-%{RELEASE}\n' 2>/dev/null")

    def _collect_apk(self):
        return self._run_cmd("apk info -v 2>/dev/null | sed 's/-r[0-9]\\+$//'")

    def _filter_interesting(self, raw_lines):
        out = []
        for line in raw_lines:
            lowered = line.lower()
            if any(pkg in lowered for pkg in self._KEY_PACKAGES):
                out.append(line)
        return out

    def run(self):
        manager = self._detect_pkg_manager()
        if not manager:
            print_error("No supported package manager found (dpkg-query/rpm/apk)")
            return False

        self._print_section("Package Vulnerability Hint")
        print_info(f"Detected package manager: {manager}")

        if manager == "dpkg":
            raw = self._collect_dpkg()
        elif manager == "rpm":
            raw = self._collect_rpm()
        else:
            raw = self._collect_apk()

        if not raw:
            print_error("Unable to list installed packages")
            return False

        lines = [line.strip() for line in raw.splitlines() if line.strip()]
        interesting = self._filter_interesting(lines)
        limit = int(self.max_results)

        self._print_section("Interesting Installed Packages")
        if not interesting:
            print_warning("No key packages found in the selected package list")
        else:
            for line in interesting[:limit]:
                print_info(line)

        print_success("Package vulnerability hint collection completed")
        return True
