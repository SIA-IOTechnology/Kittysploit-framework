from kittysploit import *
from lib.post.linux.system import System
from lib.post.linux.session import LinuxSessionMixin


class Module(Post, System, LinuxSessionMixin):
    __info__ = {
        "name": "Linux Container Escape Check",
        "description": "Assess Docker socket, capabilities, cgroups, mount namespaces, and privileged container indicators",
        "platform": Platform.LINUX,
        "author": "KittySploit Team",
        "session_type": [SessionType.SHELL, SessionType.METERPRETER, SessionType.SSH],
    'agent': {
        'risk': 'intrusive',
        'effects': ['active_exploitation'],
        'expected_requests': 4,
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

    max_findings = OptInteger(40, "Maximum lines per section", False)

    def _run(self, command: str) -> str:
        try:
            output = self.linux_execute(command)
            return output.strip() if output else ""
        except Exception:
            return ""

    def _section(self, title: str, command: str):
        print_info("-" * 80)
        print_status(title)
        output = self._run(command)
        if not output:
            print_info("  (no output)")
            return output
        for line in output.splitlines()[: int(self.max_findings or 40)]:
            print_info(f"  {line}")
        return output

    def _hint(self, findings: list):
        print_info("-" * 80)
        print_status("Escape-relevant observations")
        if not findings:
            print_info("  No strong container escape indicators detected")
            return
        for severity, message in findings:
            print_info(f"  [{severity}] {message}")

    def run(self):

        if not self.linux_require_linux():
            return False

        print_info("=" * 80)
        print_status("Container escape assessment")

        findings = []
        container_hints = self._section(
            "Container environment",
            "test -f /.dockerenv && echo /.dockerenv; "
            "test -f /run/.containerenv && echo /run/.containerenv; "
            "systemd-detect-virt -c 2>/dev/null; "
            "cat /proc/1/cgroup 2>/dev/null | head -n 8",
        )
        if any(x in (container_hints or "").lower() for x in ("docker", "container", "kubepods", "lxc")):
            findings.append(("MEDIUM", "Container-like cgroup or marker detected"))

        docker_sock = self._section(
            "Docker socket",
            "ls -l /var/run/docker.sock /run/docker.sock 2>/dev/null; "
            "getent group docker 2>/dev/null; id 2>/dev/null",
        )
        if "docker.sock" in (docker_sock or ""):
            findings.append(("HIGH", "Docker control socket present — review group membership and permissions"))
        if "docker" in (docker_sock or "").lower() and "(docker)" in (docker_sock or ""):
            findings.append(("HIGH", "Current user appears in docker group"))

        caps = self._section(
            "Capabilities",
            "grep -E 'CapEff|CapBnd|CapAmb' /proc/self/status 2>/dev/null; "
            "command -v capsh >/dev/null 2>&1 && capsh --print 2>/dev/null | head -n 25; "
            "command -v getcap >/dev/null 2>&1 && getcap -r / 2>/dev/null | head -n 25",
        )
        if caps:
            lowered = caps.lower()
            if "cap_sys_admin" in lowered or "00000020" in caps:
                findings.append(("HIGH", "CAP_SYS_ADMIN present — mount/cgroup abuse may be possible"))
            if "cap_sys_ptrace" in lowered:
                findings.append(("MEDIUM", "CAP_SYS_PTRACE present — process injection against host processes"))
            if "cap_dac_read_search" in lowered or "cap_dac_override" in lowered:
                findings.append(("MEDIUM", "Broad DAC capability — host file reads may be possible"))

        mounts = self._section(
            "Mount namespace",
            "findmnt -R / 2>/dev/null | head -n 30; "
            "grep -E ' / |docker|overlay|proc|sys|host' /proc/self/mountinfo 2>/dev/null | head -n 25",
        )
        if mounts and any(x in mounts for x in ("/host", "merged", "overlay")):
            findings.append(("MEDIUM", "Host-like or merged mounts visible — inspect for breakout paths"))

        cgroups = self._section(
            "Cgroups",
            "test -d /sys/fs/cgroup && ls /sys/fs/cgroup 2>/dev/null; "
            "cat /proc/self/cgroup 2>/dev/null; "
            "test -w /sys/fs/cgroup && echo cgroup_writable",
        )
        if "cgroup_writable" in (cgroups or ""):
            findings.append(("HIGH", "Writable cgroup hierarchy — classic container escape primitive"))

        privileged = self._section(
            "Privileged indicators",
            "grep -i privileged /proc/1/status 2>/dev/null; "
            "test -e /dev/kmsg && echo /dev/kmsg; "
            "ls /dev 2>/dev/null | grep -E 'mem$|kmem$|port$|raw$' | head -n 10",
        )
        if "/dev/kmsg" in (privileged or "") or "mem" in (privileged or ""):
            findings.append(("MEDIUM", "Sensitive device nodes exposed inside container"))

        self._hint(findings)
        print_info("=" * 80)
        print_success("Container escape check completed")
        return True
