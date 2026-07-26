#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""CVE-2026-21509 — Office Shell.Explorer.1 kill-bit posture / mitigation (post)."""

from kittysploit import *
from lib.post.windows.session import WindowsSessionMixin

_CLSID = "{EAB22AC3-30C1-11CF-A7EB-0000C05BAE0B}"
_FLAG_NAME = "Compatibility Flags"
_FLAG_VALUE = 0x400  # 1024

# Office 16.0 + ClickToRun mirrors (32/64), matching common Microsoft guidance.
_REG_PATHS = (
    rf"HKLM\SOFTWARE\Microsoft\Office\16.0\Common\COM Compatibility\{_CLSID}",
    rf"HKLM\SOFTWARE\Microsoft\Office\ClickToRun\REGISTRY\MACHINE\Software\Microsoft\Office\16.0\Common\COM Compatibility\{_CLSID}",
    rf"HKLM\SOFTWARE\WOW6432Node\Microsoft\Office\16.0\Common\COM Compatibility\{_CLSID}",
    rf"HKLM\SOFTWARE\Microsoft\Office\ClickToRun\REGISTRY\MACHINE\Software\WOW6432Node\Microsoft\Office\16.0\Common\COM Compatibility\{_CLSID}",
    # Broader Office\Common paths also cited in public guidance
    rf"HKLM\SOFTWARE\Microsoft\Office\Common\COM Compatibility\{_CLSID}",
    rf"HKLM\SOFTWARE\WOW6432Node\Microsoft\Office\Common\COM Compatibility\{_CLSID}",
)

_RELEVANT_KBS = ("KB5002694", "KB5002695", "KB5002713")


class Module(Post, WindowsSessionMixin):
    __info__ = {
        "name": "Windows Office CVE-2026-21509 kill-bit manage",
        "description": (
            "Post-exploitation module for CVE-2026-21509 (Office OLE/COM kill-bit bypass "
            "around Shell.Explorer.1 / CLSID {EAB22AC3-30C1-11CF-A7EB-0000C05BAE0B}). "
            "Checks registry Compatibility Flags=0x400, applies/removes the temporary "
            "kill-bit mitigation, checks related KBs, or writes a dummy RTF probe. "
            "Requires an admin Windows shell session. Note: the CVE bypasses kill-bit "
            "checks — registry mitigation is temporary; install Microsoft patches."
        ),
        "author": ["suuhm", "KittySploit Team"],
        "cve": ["CVE-2026-21509"],
        "platform": Platform.WINDOWS,
        "session_type": [SessionType.METERPRETER, SessionType.SHELL],
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2026-21509",
            "https://msrc.microsoft.com/",
            "https://orca.security/resources/blog/cve-2026-21509-microsoft-office-zero-day-exploit/",
        ],
        "tags": [
            "office",
            "ole",
            "com",
            "kill-bit",
            "hardening",
            "cve-2026-21509",
        ],
        "agent": {
            "risk": "intrusive",
            "effects": ["active_exploitation"],
            "expected_requests": 6,
            "reversible": True,
            "approval_required": True,
            "produces": ["risk_signals"],
            "cost": 1.0,
            "noise": 0.3,
            "value": 0.9,
            "requires": {"capabilities_any": ["shell"], "capabilities_all": []},
            "chain": {
                "consumes_capabilities": ["shell"],
                "produces_capabilities": [],
            },
        },
    }

    action = OptString(
        "check",
        "Action: check | apply | remove | kb | write_test_rtf",
        required=False,
    )
    require_admin = OptBool(
        True,
        "Require Administrator for apply/remove (check/kb can run without)",
        required=False,
    )
    write_all_paths = OptBool(
        True,
        "Apply/remove on all known 32/64 + ClickToRun registry paths",
        required=False,
        advanced=True,
    )

    def _query_flag(self, path: str) -> str:
        out = self.win_execute(f'reg query "{path}" /v "{_FLAG_NAME}"', timeout=8)
        return out or ""

    def _parse_dword(self, reg_output: str):
        # Typical: Compatibility Flags    REG_DWORD    0x400
        for line in (reg_output or "").splitlines():
            if _FLAG_NAME.lower() in line.lower() and "REG_DWORD" in line.upper():
                parts = line.strip().split()
                for token in reversed(parts):
                    if token.lower().startswith("0x"):
                        try:
                            return int(token, 16)
                        except ValueError:
                            return None
                    if token.isdigit():
                        try:
                            return int(token)
                        except ValueError:
                            return None
        return None

    def _check(self) -> bool:
        print_status(f"Checking kill-bit for {_CLSID} (Compatibility Flags=0x{_FLAG_VALUE:X})")
        protected_paths = []
        missing_paths = []
        for path in _REG_PATHS:
            out = self._query_flag(path)
            value = self._parse_dword(out)
            if value == _FLAG_VALUE:
                print_success(f"ACTIVE: {path}")
                protected_paths.append(path)
            elif value is not None:
                print_warning(f"Present but unexpected value 0x{value:X}: {path}")
                missing_paths.append(path)
            else:
                print_info(f"Missing/absent: {path}")
                missing_paths.append(path)

        if protected_paths:
            print_success(
                f"Kill-bit present on {len(protected_paths)} path(s). "
                "Still install Microsoft patches — CVE-2026-21509 can bypass kill-bits."
            )
            return True

        print_warning(
            "Kill-bit NOT set on known paths — host lacks recommended temporary mitigation"
        )
        return False

    def _apply(self) -> bool:
        if self.require_admin and not self.win_is_admin():
            print_error("Administrator privileges are required to apply kill-bit")
            return False

        print_status(f"Applying Compatibility Flags=0x{_FLAG_VALUE:X} ...")
        patched = 0
        for path in _REG_PATHS:
            add = self.win_execute(
                f'reg add "{path}" /v "{_FLAG_NAME}" /t REG_DWORD /d {_FLAG_VALUE} /f',
                timeout=10,
            )
            ok = "successfully" in (add or "").lower() or "réussi" in (add or "").lower()
            # Verify even if language differs
            value = self._parse_dword(self._query_flag(path))
            if ok or value == _FLAG_VALUE:
                print_success(f"Set: {path}")
                patched += 1
            else:
                print_warning(f"Failed: {path} ({add or 'no output'})")
                if not self.write_all_paths:
                    break

        if patched:
            print_success(f"Kill-bit applied on {patched} path(s). Restart Office apps.")
            print_warning(
                "This is a temporary mitigation; CVE-2026-21509 is a kill-bit bypass — patch Office."
            )
            return True
        print_error("No registry paths were patched")
        return False

    def _remove(self) -> bool:
        if self.require_admin and not self.win_is_admin():
            print_error("Administrator privileges are required to remove kill-bit")
            return False

        print_warning("Removing kill-bit Compatibility Flags (only if fully patched)...")
        removed = 0
        for path in _REG_PATHS:
            out = self.win_execute(
                f'reg delete "{path}" /v "{_FLAG_NAME}" /f',
                timeout=8,
            )
            value = self._parse_dword(self._query_flag(path))
            if value is None:
                # deleted or never present
                if "successfully" in (out or "").lower() or "réussi" in (out or "").lower() or "ERROR" in (out or "").upper():
                    print_info(f"Cleared/absent: {path}")
                    removed += 1
                else:
                    print_info(f"Absent: {path}")
            else:
                print_warning(f"Still present (0x{value:X}): {path}")
        print_status(f"Processed {removed} path(s)")
        return True

    def _kb(self) -> bool:
        print_status(f"Checking hotfixes related to CVE-2026-21509: {', '.join(_RELEVANT_KBS)}")
        script = r"""
$ErrorActionPreference = 'SilentlyContinue'
$want = @('KB5002694','KB5002695','KB5002713')
$hits = Get-HotFix | Where-Object {
    $_.HotFixID -match '500269|500271' -or ($want -contains $_.HotFixID)
} | Select-Object HotFixID, InstalledOn, Description
if ($hits) {
    $hits | Format-Table -AutoSize | Out-String -Width 200
} else {
    'NO_MATCHING_KB'
}
"""
        out = self.win_run_powershell(script, timeout=45)
        if not out:
            print_error("Could not query hotfixes (Get-HotFix)")
            return False
        if "NO_MATCHING_KB" in out:
            print_warning("No KB5002694/KB5002695/KB5002713-style hotfixes found via Get-HotFix")
            print_info("Verify Microsoft 365/Click-to-Run build updates separately")
            return False
        print_success("Matching hotfix entries:")
        print_info(out.strip())
        return True

    def _write_test_rtf(self) -> bool:
        script = rf"""
$ErrorActionPreference = 'Stop'
$path = Join-Path $env:TEMP 'CVE202621509_KillBit_Test.rtf'
$content = '{{\rtf1\ansi Kill-Bit probe for {_CLSID}}}'
Set-Content -Path $path -Value $content -Encoding ASCII
Write-Output $path
"""
        out = self.win_run_powershell(script, timeout=15)
        path = (out or "").strip().splitlines()[-1] if out else ""
        if not path or ":" not in path:
            print_error("Failed to write test RTF")
            return False
        print_success(f"Test RTF written: {path}")
        print_info("Open in Word: kill-bit active → object activation error; inactive → COM may load")
        print_warning("CVE-2026-21509 can bypass kill-bit — treat this only as a coarse probe")
        return True

    def run(self):
        if not self.win_require_windows():
            return False
        if not self.win_require_powershell():
            return False

        action = str(self.action or "check").strip().lower()
        print_status(f"CVE-2026-21509 Office kill-bit manage — action={action}")

        if action == "check":
            return self._check()
        if action == "apply":
            return self._apply()
        if action == "remove":
            return self._remove()
        if action in ("kb", "kb_check", "hotfix"):
            return self._kb()
        if action in ("write_test_rtf", "test_rtf", "rtf"):
            return self._write_test_rtf()

        print_error(f"Unknown action: {action}")
        print_info("Valid: check | apply | remove | kb | write_test_rtf")
        return False
