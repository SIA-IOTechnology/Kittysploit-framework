from kittysploit import *
from lib.post.linux.system import System
import re


class Module(Post, System):

    __info__ = {
        "name": "Linux Gather Protection Enumeration",
        "description": "Enumerate Linux hardening mechanisms and installed security software",
        "platform": Platform.LINUX,
        "author": "ohdae, KittySploit Team",
        "session_type": [SessionType.SHELL, SessionType.METERPRETER, SessionType.SSH],
    }

    SECURITY_EXECUTABLES = {
        "aa-status": "AppArmor",
        "aide": "Advanced Intrusion Detection Environment (AIDE)",
        "apparmor": "AppArmor",
        "auditd": "auditd",
        "avast": "Avast",
        "bastille": "Bastille",
        "bulldog": "Bulldog",
        "chkrootkit": "chkrootkit",
        "clamav": "ClamAV",
        "elastic-agent": "Elastic Security",
        "fail2ban-client": "fail2ban",
        "falco": "Falco Runtime Security",
        "firewall-cmd": "firewalld",
        "firejail": "Firejail",
        "firestarter": "Firestarter",
        "fw-settings": "Uncomplicated FireWall (UFW)",
        "getenforce": "SELinux",
        "gradm": "grsecurity",
        "gradm2": "grsecurity",
        "honeyd": "Honeyd",
        "iptables": "iptables",
        "jailkit": "jailkit",
        "logrotate": "logrotate",
        "logwatch": "logwatch",
        "lynis": "lynis",
        "nagios": "nagios",
        "nft": "nftables",
        "opensnitch": "OpenSnitch",
        "ossec-control": "OSSEC HIDS",
        "osqueryd": "osquery",
        "oz-seccomp": "OZ",
        "paxctl": "PaX",
        "paxctld": "PaX",
        "paxtest": "PaX",
        "proxychains": "ProxyChains",
        "psad": "psad",
        "rkhunter": "rkhunter",
        "snort": "snort",
        "suricata": "Suricata IDS/IPS",
        "sysdig": "Sysdig",
        "tcpdump": "tcpdump",
        "thpot": "thpot",
        "tiger": "tiger",
        "tripwire": "tripwire",
        "ufw": "Uncomplicated FireWall (UFW)",
        "wazuh-control": "Wazuh",
        "wireshark": "Wireshark",
        "zeek": "Zeek Network Monitor",
    }

    SECURITY_PATHS = {
        "/bin/logrhythm": "LogRhythm Axon",
        "/etc/aide/aide.conf": "Advanced Intrusion Detection Environment (AIDE)",
        "/etc/chkrootkit": "chkrootkit",
        "/etc/clamd.d/scan.conf": "ClamAV",
        "/etc/fail2ban": "fail2ban",
        "/etc/falco": "Falco Runtime Security",
        "/etc/firewalld": "firewalld",
        "/etc/fluent-bit": "Fluent Bit Log Collector",
        "/etc/freshclam.conf": "ClamAV",
        "/etc/init.d/avast": "Avast",
        "/etc/init.d/avgd": "AVG",
        "/etc/init.d/ds_agent": "Trend Micro Deep Instinct",
        "/etc/init.d/fortisiem-linux-agent": "Fortinet FortiSIEM",
        "/etc/init.d/kics": "Kaspersky Industrial CyberSecurity",
        "/etc/init.d/limacharlie": "LimaCharlie Agent",
        "/etc/init.d/qualys-cloud-agent": "Qualys EDR Cloud Agent",
        "/etc/init.d/scsm": "LogRhythm System Monitor",
        "/etc/init.d/sisamdagent": "Symantec EDR",
        "/etc/init.d/splx": "Trend Micro Server Protect",
        "/etc/init.d/threatconnect-envsvr": "ThreatConnect",
        "/etc/logrhythm": "LogRhythm Axon",
        "/etc/nftables.conf": "nftables",
        "/etc/opt/f-secure": "WithSecure (F-Secure)",
        "/etc/osquery": "osquery",
        "/etc/otelcol-sumo/sumologic.yaml": "Sumo Logic OTEL Collector",
        "/etc/opensnitchd": "OpenSnitch",
        "/etc/rkhunter.conf": "rkhunter",
        "/etc/safedog/sdsvrd.conf": "Safedog",
        "/etc/safedog/server/conf/sdsvrd.conf": "Safedog",
        "/etc/suricata": "Suricata IDS/IPS",
        "/etc/tripwire": "TripWire",
        "/opt/COMODO": "Comodo AV",
        "/opt/CrowdStrike": "CrowdStrike",
        "/opt/FortiEDRCollector": "Fortinet FortiEDR",
        "/opt/McAfee": "FireEye/McAfee/Trellix Agent",
        "/opt/SumoCollector": "Sumo Logic Cloud SIEM",
        "/opt/Symantec": "Symantec EDR",
        "/opt/Tanium": "Tanium",
        "/opt/Trellix": "FireEye/McAfee/Trellix SIEM Collector",
        "/opt/avg": "AVG",
        "/opt/bitdefender-security-tools/bin/bdconfigure": "Bitdefender EDR",
        "/opt/cisco/amp/bin/ampcli": "Cisco Secure Endpoint",
        "/opt/cyberark": "CyberArk",
        "/opt/ds_agent/dsa": "Trend Micro Deep Security Agent",
        "/opt/f-secure": "WithSecure (F-Secure)",
        "/opt/fireeye": "FireEye/Trellix EDR",
        "/opt/fortinet/fortisiem": "Fortinet FortiSIEM",
        "/opt/isec": "FireEye/Trellix Endpoint Security",
        "/opt/kaspersky": "Kaspersky",
        "/opt/logrhythm/scsm": "LogRhythm System Monitor",
        "/opt/osquery": "osquery",
        "/opt/secureworks": "Secureworks",
        "/opt/sentinelone/bin/sentinelctl": "SentinelOne",
        "/opt/splunkforwarder": "Splunk",
        "/opt/threatbook/OneAV": "threatbook.OneAV",
        "/opt/threatconnect-envsvr/": "ThreatConnect",
        "/opt/traps/bin/cytool": "Palo Alto Networks Cortex XDR",
        "/opt/wazuh": "Wazuh",
        "/sf/edr/agent/bin/edr_agent": "Sangfor EDR",
        "/titan/agent/agent_update.sh": "Titan Agent",
        "/usr/bin/linep": "Group-iB XDR Endpoint Agent",
        "/usr/bin/oneav_start": "threatbook.OneAV",
        "/usr/lib/Acronis": "Acronis Cyber Protect",
        "/usr/lib/symantec/status.sh": "Symantec Linux Agent",
        "/usr/local/bin/intezer-analyze": "Intezer",
        "/usr/local/qualys": "Qualys EDR Cloud Agent",
        "/usr/local/rocketcyber": "Kaseya RocketCyber",
        "/var/lib/avast/Setup/avast.vpsupdate": "Avast",
        "/var/log/checkpoint": "Checkpoint",
        "/var/ossec": "OSSEC/Wazuh HIDS",
        "/var/pt": "PT Swarm",
    }

    def run(self):
        print_status("Enumerating Linux protections and security software...")
        self._print_host_info()

        print_status("Finding system protections...")
        self._check_hardening()

        print_status("Finding installed applications via executables...")
        self._find_executables()

        print_status("Finding installed applications via filesystem paths...")
        self._find_paths()

        print_success("Protection enumeration completed")
        return True

    def _print_host_info(self):
        distro = self.get_sysinfo().get("distro", "linux")
        kernel = self._clean_text(self.cmd_exec("uname -r 2>/dev/null"))
        hostname = self._clean_text(self.cmd_exec("hostname 2>/dev/null"))
        if hostname:
            print_info(f"Host: {hostname}")
        print_info(f"Distro: {distro}")
        if kernel:
            print_info(f"Kernel: {kernel}")

    def _clean_text(self, text):
        if not text:
            return ""
        cleaned = re.sub(r"\x1b\[[0-9;]*[A-Za-z]", "", str(text))
        cleaned = cleaned.replace("\r", "\n")
        lines = []
        for line in cleaned.splitlines():
            line = line.strip()
            if not line:
                continue
            if line.startswith("[default]"):
                continue
            lines.append(line)
        return lines[-1] if lines else ""

    def _read_proc_flag(self, path):
        value = self._clean_text(self.cmd_exec(f"cat {path} 2>/dev/null"))
        return value if value else None

    def _is_true(self, path, true_values):
        value = self._read_proc_flag(path)
        if value is None:
            return None
        return value in true_values

    def _command_has_keyword(self, command, keywords):
        output = self._clean_text(self.cmd_exec(command))
        if not output:
            return False
        lowered = output.lower()
        return any(k in lowered for k in keywords)

    def _check_hardening(self):
        findings = []

        checks = [
            ("ASLR is enabled", self._is_true("/proc/sys/kernel/randomize_va_space", {"1", "2"})),
            ("dmesg restriction is enabled", self._is_true("/proc/sys/kernel/dmesg_restrict", {"1"})),
            ("Kernel pointer restriction is enabled", self._is_true("/proc/sys/kernel/kptr_restrict", {"1", "2"})),
            ("Unprivileged BPF is disabled", self._is_true("/proc/sys/kernel/unprivileged_bpf_disabled", {"1", "2"})),
            ("Yama is installed and enabled", self._is_true("/proc/sys/kernel/yama/ptrace_scope", {"1", "2", "3"})),
            ("User namespaces are enabled (unprivileged may be available)", self._is_true("/proc/sys/kernel/unprivileged_userns_clone", {"1"})),
            ("SMEP is enabled", self._command_has_keyword("grep -m1 -i '^flags' /proc/cpuinfo 2>/dev/null", [" smep "])),
            ("SMAP is enabled", self._command_has_keyword("grep -m1 -i '^flags' /proc/cpuinfo 2>/dev/null", [" smap "])),
            ("KPTI is enabled", self._command_has_keyword("grep -m1 -i '^flags' /proc/cpuinfo 2>/dev/null", [" pti "])),
            ("grsecurity is installed", self._is_true("/proc/sys/kernel/grsecurity/grsec_enabled", {"1"})),
            ("LKRG is installed", self._command_has_keyword("lsmod 2>/dev/null", ["p_lkrg"])),
            ("PaX is installed", self._command_has_keyword("lsmod 2>/dev/null", ["pax", "grsec"])),
        ]

        for message, result in checks:
            if result is True:
                print_success(message)
                findings.append(message)

        selinux_mode = self._clean_text(self.cmd_exec("getenforce 2>/dev/null"))
        if selinux_mode:
            mode = selinux_mode.lower()
            if mode == "enforcing":
                msg = "SELinux is installed and enforcing"
                print_success(msg)
                findings.append(msg)
            elif mode in {"permissive", "disabled"}:
                msg = f"SELinux is installed, mode: {selinux_mode}"
                print_info(msg)
                findings.append(msg)

        # Check AppArmor separately (common LSM on Debian/Ubuntu systems)
        apparmor_enabled = self._is_true("/sys/module/apparmor/parameters/enabled", {"Y"})
        if apparmor_enabled is True:
            msg = "AppArmor is enabled"
            print_success(msg)
            findings.append(msg)

        if not findings:
            print_warning("No hardening feature positively detected with current checks")

    def _is_safe_path(self, value):
        if not value:
            return False
        if not value.startswith("/"):
            return False
        if " not found" in value.lower():
            return False
        if "$" in value:
            return False
        return True

    def _find_executables(self):
        found = 0
        for binary, appname in self.SECURITY_EXECUTABLES.items():
            if not self.command_exists(binary):
                continue

            path = self._clean_text(self.cmd_exec(f"command -v {binary} 2>/dev/null"))
            if not self._is_safe_path(path):
                continue

            print_success(f"{binary} found: {path}")
            print_info(f"  Product: {appname}")
            found += 1

        if found == 0:
            print_warning("No known security executable found in PATH")

    def _path_exists(self, path):
        output = self._clean_text(self.cmd_exec(f'test -e "{path}" && echo true'))
        return output == "true"

    def _find_paths(self):
        found = 0
        for path, appname in self.SECURITY_PATHS.items():
            try:
                if not self._path_exists(path):
                    continue
                print_success(f"{appname} found: {path}")
                found += 1
            except Exception:
                print_warning(f"Unable to determine state of {appname}")

        if found == 0:
            print_warning("No known security software path detected")
