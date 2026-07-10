#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Expected telemetry profiles for post-exploitation modules (Windows & Linux).

Each entry documents what a blue/purple team should expect to see when an operator
runs the corresponding KittySploit post module.  Consumed by:

- ``DetectionPackGenerator`` — enriches Sigma rules, expected log fixtures, EDR hypotheses
- ``purple_detection_export`` — batch-generates detection packs from this registry
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

# Keys are module paths as used in KittySploit (modules/post/...)
POST_TELEMETRY: Dict[str, Dict[str, Any]] = {
    "modules/post/shell/windows/gather/edr_audit": {
        "mitre": ["T1518.001", "T1082"],
        "edr_hypotheses": [
            "Get-MpComputerStatus invoked — Defender inventory via WMI/Defender API.",
            "tasklist filters for MsMpEng, SenseIR, CSFalconService, Sysmon64, etc.",
            "Registry read of HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\RunAsPPL.",
            "Win32_DeviceGuard WMI query for Credential Guard / VBS status.",
        ],
        "expected_events": [
            {"source": "edr.process", "event_id": "4688", "process": {"name": "powershell.exe"}, "note": "Defender audit"},
            {"source": "windows.defender", "event": "inventory", "note": "Get-MpComputerStatus"},
            {"source": "edr.process", "event_id": "4688", "process": {"name": "tasklist.exe"}},
        ],
        "sigma_hints": [
            "Image|endswith: 'powershell.exe' AND CommandLine|contains: 'Get-MpComputerStatus'",
            "CommandLine|contains: 'Win32_DeviceGuard'",
        ],
    },
    "modules/post/shell/windows/gather/runasppl_audit": {
        "mitre": ["T1518.001", "T1003.001"],
        "edr_hypotheses": [
            "RunAsPPL registry value read — predicts LSASS PPL protection.",
            "Get-Process lsass ProtectionLevel property access on Windows 10+.",
            "Operator receives dump technique recommendation (comsvcs vs external tool).",
        ],
        "expected_events": [
            {"source": "windows.registry", "key": "RunAsPPL", "action": "query"},
            {"source": "edr.process", "process": {"name": "powershell.exe"}, "target": "lsass.exe"},
        ],
        "sigma_hints": [
            "CommandLine|contains: 'RunAsPPL'",
            "CommandLine|contains: 'ProtectionLevel'",
        ],
    },
    "modules/post/shell/windows/manage/amsi_bypass": {
        "mitre": ["T1562.001"],
        "edr_hypotheses": [
            "In-memory patch of AmsiUtils.amsiInitFailed or AmsiContext via reflection.",
            "Follow-on PowerShell script execution without AMSI block on signature probe.",
        ],
        "expected_events": [
            {"source": "edr.script", "event_id": "4104", "note": "Script block if logging still enabled"},
            {"source": "edr.memory", "note": "RWX or byte patch in amsi.dll / automation assembly"},
        ],
        "sigma_hints": [
            "CommandLine|contains: 'AmsiUtils'",
            "CommandLine|contains: 'amsiInitFailed'",
        ],
    },
    "modules/post/shell/windows/manage/etw_patch": {
        "mitre": ["T1562.006"],
        "edr_hypotheses": [
            "VirtualProtect on ntdll!EtwEventWrite followed by RET patch.",
            "Reduced PowerShell operational telemetry for current process.",
        ],
        "expected_events": [
            {"source": "edr.memory", "module": "ntdll.dll", "export": "EtwEventWrite"},
        ],
        "sigma_hints": [
            "CommandLine|contains: 'EtwEventWrite'",
            "CommandLine|contains: 'VirtualProtect'",
        ],
    },
    "modules/post/shell/windows/manage/defender_exclusion": {
        "mitre": ["T1562.001"],
        "edr_hypotheses": [
            "Add-MpPreference -ExclusionPath — lower noise than full disable.",
            "Optional Set-MpPreference -Disable* triggers Defender alert event 5001.",
        ],
        "expected_events": [
            {"source": "windows.defender", "event_id": "5007", "note": "Exclusion added"},
            {"source": "windows.defender", "event_id": "5001", "note": "If disable_realtime=true"},
        ],
        "sigma_hints": [
            "CommandLine|contains: 'Add-MpPreference'",
            "CommandLine|contains: 'Set-MpPreference'",
        ],
    },
    "modules/post/shell/windows/manage/disable_ps_logging": {
        "mitre": ["T1562.002"],
        "edr_hypotheses": [
            "Registry policy keys under HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell set to 0.",
            "Future script execution may lack 4104/4103 events.",
        ],
        "expected_events": [
            {"source": "windows.registry", "key": "ScriptBlockLogging", "action": "set"},
            {"source": "windows.registry", "key": "ModuleLogging", "action": "set"},
        ],
        "sigma_hints": [
            "CommandLine|contains: 'EnableScriptBlockLogging'",
        ],
    },
    "modules/post/shell/windows/manage/clear_event_logs": {
        "mitre": ["T1070.001"],
        "edr_hypotheses": [
            "wevtutil cl Security/System/Application — high visibility.",
            "Event ID 1102 (Security log cleared) and 104 (log cleared).",
        ],
        "expected_events": [
            {"source": "windows.security", "event_id": "1102"},
            {"source": "windows.system", "event_id": "104"},
            {"source": "edr.process", "process": {"name": "wevtutil.exe"}},
        ],
        "sigma_hints": [
            "Image|endswith: 'wevtutil.exe'",
            "CommandLine|contains: 'cl Security'",
        ],
    },
    "modules/post/shell/windows/gather/dump_lsass": {
        "mitre": ["T1003.001"],
        "edr_hypotheses": [
            "MiniDumpWriteDump via PowerShell WindowsErrorReporting wrapper on lsass.exe.",
            "Handle open on lsass + .dmp file write under %TEMP%.",
        ],
        "expected_events": [
            {"source": "edr.process", "target": "lsass.exe", "access": "dump"},
            {"source": "edr.file", "extension": ".dmp"},
            {"source": "windows.security", "event_id": "4656", "note": "Handle to lsass"},
        ],
        "sigma_hints": [
            "CommandLine|contains: 'MiniDumpWriteDump'",
            "TargetImage|endswith: 'lsass.exe'",
        ],
    },
    "modules/post/shell/windows/gather/dump_lsass_comsvcs": {
        "mitre": ["T1003.001"],
        "edr_hypotheses": [
            "rundll32.exe comsvcs.dll MiniDump against lsass PID.",
            "Common stealthier alternative to direct PowerShell dump.",
        ],
        "expected_events": [
            {"source": "edr.process", "parent": "rundll32.exe", "command_line|contains": "comsvcs.dll"},
            {"source": "edr.file", "extension": ".dmp"},
        ],
        "sigma_hints": [
            "CommandLine|contains: 'comsvcs.dll'",
            "CommandLine|contains: 'MiniDump'",
        ],
    },
    "modules/post/shell/windows/manage/external_tool_runner": {
        "mitre": ["T1105", "T1003.001"],
        "edr_hypotheses": [
            "Binary upload to %TEMP% via chunked base64 PowerShell writes.",
            "Execution of operator-supplied tool (nanodump, PPLdump, etc.).",
        ],
        "expected_events": [
            {"source": "edr.file", "action": "create", "note": "Uploaded tool"},
            {"source": "edr.process", "note": "Unknown signed/unsigned binary from temp"},
        ],
        "sigma_hints": [
            "CommandLine|contains: 'FromBase64String'",
            "Image|contains: '\\\\Temp\\\\'",
        ],
    },
    "modules/post/shell/windows/gather/lsass_dump_chain": {
        "mitre": ["T1003.001", "T1562.001"],
        "edr_hypotheses": [
            "Chained post-ex: audit → AMSI bypass → comsvcs dump → optional external tool → PS fallback.",
            "Multiple high-fidelity signals in short window — ideal purple-team correlation test.",
        ],
        "expected_events": [
            {"source": "correlation", "note": "Sequence of audit + evasion + dump within 15m"},
        ],
        "sigma_hints": [
            "correlation: amsi bypass followed by comsvcs MiniDump within 15m",
        ],
    },
    # --- Linux post-exploitation ---
    "modules/post/shell/linux/gather/execute": {
        "mitre": ["T1059.004"],
        "edr_hypotheses": [
            "Arbitrary shell command execution via reverse/bind session.",
            "Meterpreter sessions prefix commands with shell — child /bin/sh or bash spawned.",
        ],
        "expected_events": [
            {"source": "linux.audit", "type": "EXECVE", "note": "auditd if enabled"},
            {"source": "edr.process", "parent": "bash|sh", "note": "Command child process"},
        ],
        "sigma_hints": [
            "ParentCommandLine|contains: '/bin/sh'",
            "process.name: bash AND user.id: www-data",
        ],
    },
    "modules/post/shell/linux/gather/enum_users": {
        "mitre": ["T1087.001", "T1033"],
        "edr_hypotheses": [
            "Reads /etc/passwd, /etc/group, last/lastlog, sudoers, authorized_keys paths.",
            "Grep on auth.log for failed/successful logins.",
        ],
        "expected_events": [
            {"source": "linux.file", "path": "/etc/passwd", "action": "read"},
            {"source": "linux.file", "path": "/etc/shadow", "action": "read", "note": "If root"},
            {"source": "edr.process", "command_line|contains": "lastlog"},
        ],
        "sigma_hints": [
            "CommandLine|contains: '/etc/passwd'",
            "CommandLine|contains: 'authorized_keys'",
        ],
    },
    "modules/post/shell/linux/gather/gather_credentials": {
        "mitre": ["T1552.001", "T1552.004", "T1552.003"],
        "edr_hypotheses": [
            "find/grep over home, /root, /var/www for SSH keys, .env, API tokens, DB creds.",
            "Reads /etc/shadow if UID 0; scans .bash_history and config files.",
        ],
        "expected_events": [
            {"source": "linux.file", "pattern": "*.pem|id_rsa|id_ed25519", "action": "read"},
            {"source": "linux.file", "pattern": ".env|.pgpass|.aws", "action": "read"},
            {"source": "edr.process", "command_line|contains": "find /home"},
        ],
        "sigma_hints": [
            "CommandLine|contains: 'id_rsa'",
            "CommandLine|contains: '.env'",
        ],
    },
    "modules/post/shell/linux/gather/enum_protections": {
        "mitre": ["T1518.001", "T1082"],
        "edr_hypotheses": [
            "Enumerates AppArmor/SELinux mode, grsecurity, fail2ban, auditd, clamav, aide.",
            "Kernel version and security module status via uname/getenforce/aa-status.",
        ],
        "expected_events": [
            {"source": "edr.process", "command_line|contains": "getenforce"},
            {"source": "edr.process", "command_line|contains": "aa-status"},
            {"source": "linux.file", "path": "/proc/sys/kernel/yama/ptrace_scope", "action": "read"},
        ],
        "sigma_hints": [
            "CommandLine|contains: 'getenforce'",
            "CommandLine|contains: 'fail2ban'",
        ],
    },
    "modules/post/shell/linux/gather/suid_sgid_hunt": {
        "mitre": ["T1548.001"],
        "edr_hypotheses": [
            "find -perm -4000 or -2000 across filesystem — GTFOBins-style privesc recon.",
            "High inode walk volume on large disks.",
        ],
        "expected_events": [
            {"source": "edr.process", "command_line|contains": "-perm -4000"},
            {"source": "edr.process", "command_line|contains": "-perm -2000"},
        ],
        "sigma_hints": [
            "CommandLine|contains: '-perm -4000'",
            "CommandLine|contains: 'find / -perm'",
        ],
    },
    "modules/post/shell/linux/gather/persistence_audit": {
        "mitre": ["T1547"],
        "edr_hypotheses": [
            "Scans cron, systemd units, profile.d, rc.local, ld.so.preload for persistence.",
            "Read-only recon — useful baseline before/after red team.",
        ],
        "expected_events": [
            {"source": "linux.file", "path": "/etc/crontab", "action": "read"},
            {"source": "linux.file", "path": "/etc/ld.so.preload", "action": "read"},
            {"source": "edr.process", "command_line|contains": "systemctl list"},
        ],
        "sigma_hints": [
            "CommandLine|contains: 'ld.so.preload'",
            "CommandLine|contains: 'crontab'",
        ],
    },
    "modules/post/shell/linux/manage/flush_firewall_rules": {
        "mitre": ["T1562.004"],
        "edr_hypotheses": [
            "iptables/ip6tables -F and policy ACCEPT — disables host firewall.",
            "Requires CAP_NET_ADMIN or root.",
        ],
        "expected_events": [
            {"source": "linux.audit", "type": "SYSCALL", "exe": "iptables", "note": "auditd"},
            {"source": "edr.process", "command_line|contains": "iptables -F"},
        ],
        "sigma_hints": [
            "CommandLine|contains: 'iptables -F'",
            "CommandLine|contains: 'ip6tables -F'",
        ],
    },
    "modules/post/shell/linux/persistence/ssh_authorized_keys": {
        "mitre": ["T1098.004"],
        "edr_hypotheses": [
            "Appends SSH public key to ~/.ssh/authorized_keys.",
            "chmod 600 on keys file; may create ~/.ssh with mode 700.",
        ],
        "expected_events": [
            {"source": "linux.file", "path": "authorized_keys", "action": "modify"},
            {"source": "linux.audit", "type": "PATH", "name": "authorized_keys"},
        ],
        "sigma_hints": [
            "file.path|endswith: 'authorized_keys' AND file.action: write",
        ],
    },
    "modules/post/shell/linux/persistence/cron_job": {
        "mitre": ["T1053.003"],
        "edr_hypotheses": [
            "Writes user or system crontab entry for callback/payload execution.",
            "Periodic execution at configured interval.",
        ],
        "expected_events": [
            {"source": "linux.file", "path": "/etc/cron.d|crontab", "action": "modify"},
            {"source": "edr.process", "parent": "cron", "note": "At schedule fire"},
        ],
        "sigma_hints": [
            "file.path|contains: 'cron'",
            "CommandLine|contains: 'crontab'",
        ],
    },
    "modules/post/shell/linux/persistence/ld_preload": {
        "mitre": ["T1574.006"],
        "edr_hypotheses": [
            "Compiles and installs shared object; writes /etc/ld.so.preload.",
            "Processes inherit malicious library on next exec.",
        ],
        "expected_events": [
            {"source": "linux.file", "path": "/etc/ld.so.preload", "action": "modify"},
            {"source": "edr.process", "command_line|contains": "gcc|cc -shared"},
        ],
        "sigma_hints": [
            "file.path: '/etc/ld.so.preload'",
            "CommandLine|contains: '-shared'",
        ],
    },
    "modules/post/shell/linux/exploits/dirty_frag_lpe": {
        "mitre": ["T1068", "T1203"],
        "edr_hypotheses": [
            "Binary upload to /tmp via chunked base64 printf writes.",
            "Kernel exploit execution — AF_ALG/rxrpc page cache corruption for root.",
        ],
        "expected_events": [
            {"source": "edr.file", "path": "/tmp", "action": "create", "note": "Uploaded exploit"},
            {"source": "linux.audit", "type": "SYSCALL", "note": "setuid after successful exploit"},
            {"source": "edr.process", "note": "Unknown ELF from /tmp executed"},
        ],
        "sigma_hints": [
            "file.path|startswith: '/tmp/' AND file.action: create",
            "CommandLine|contains: 'base64 -d'",
        ],
    },
}


def normalize_module_path(path: str) -> str:
    path = (path or "").strip().replace("\\", "/")
    if path.endswith(".py"):
        path = path[:-3]
    if not path.startswith("modules/"):
        if path.startswith("post/"):
            path = "modules/" + path
    return path


def get_post_telemetry(module_path: str) -> Optional[Dict[str, Any]]:
    return POST_TELEMETRY.get(normalize_module_path(module_path))


def enrich_edr_hypotheses(base_lines: List[str], module_path: str) -> List[str]:
    profile = get_post_telemetry(module_path)
    if not profile:
        return base_lines
    extra = profile.get("edr_hypotheses") or []
    if not extra:
        return base_lines
    lines = list(base_lines)
    lines.extend(["", "## Post-Module Telemetry Profile", ""])
    for item in extra:
        lines.append(f"- {item}")
    mitre = profile.get("mitre") or []
    if mitre:
        lines.append("")
        lines.append(f"MITRE: {', '.join(mitre)}")
    return lines


def enrich_expected_logs(base: Dict[str, Any], module_path: str) -> Dict[str, Any]:
    profile = get_post_telemetry(module_path)
    if not profile:
        return base
    merged = dict(base)
    merged["post_telemetry"] = True
    if profile.get("mitre"):
        merged["mitre"] = profile["mitre"]
    if profile.get("expected_events"):
        merged["expected_events"] = list(merged.get("expected_events") or []) + profile["expected_events"]
    if profile.get("sigma_hints"):
        merged["sigma_hints"] = profile["sigma_hints"]
    return merged
