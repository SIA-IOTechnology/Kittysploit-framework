#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
CVE-2026-41091 / CVE-2026-45498 — Microsoft Defender engine/platform version audit (post).

Passive gather: queries Get-MpComputerStatus and Defender processes on a Windows session.
Does not exploit LPE/DoS — only reports whether versions are below fixed thresholds.
"""

from kittysploit import *

from lib.post.windows.session import WindowsSessionMixin

# Fixed floors (May 2026 Patch Tuesday / MPE + Antimalware Platform updates)
_FIXED_ENGINE = "1.1.26040.8"  # CVE-2026-41091 (LPE / improper link resolution in mpengine)
_FIXED_PLATFORM = "4.18.26040.7"  # CVE-2026-45498 (DoS / Antimalware Platform)


class Module(Post, WindowsSessionMixin):
    __info__ = {
        "name": "Windows Gather Defender CVE-2026-41091 / CVE-2026-45498 Audit",
        "description": (
            "Post gather for Microsoft Defender CVE-2026-41091 (LPE via Malware Protection "
            "Engine link-following) and CVE-2026-45498 (Antimalware Platform DoS). "
            "Reads AMEngineVersion / AMProductVersion via Get-MpComputerStatus, compares "
            f"against fixed floors {_FIXED_ENGINE} / {_FIXED_PLATFORM}, and lists MsMpEng/"
            "NisSrv/Sense processes. Passive — no exploit payload. Companion to "
            "post/shell/windows/gather/defender_posture for full preference audit."
        ),
        "author": ["KittySploit Team"],
        "cve": ["CVE-2026-41091", "CVE-2026-45498"],
        "platform": Platform.WINDOWS,
        "session_type": [SessionType.METERPRETER, SessionType.SHELL],
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2026-41091",
            "https://nvd.nist.gov/vuln/detail/CVE-2026-45498",
            "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-41091",
            "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-45498",
            "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
        ],
        "tags": [
            "defender",
            "gather",
            "lpe",
            "dos",
            "cve-2026-41091",
            "cve-2026-45498",
            "kev",
        ],
        "agent": {
            "risk": "passive",
            "effects": ["reconnaissance"],
            "expected_requests": 2,
            "reversible": True,
            "approval_required": False,
            "produces": ["risk_signals"],
            "cost": 0.4,
            "noise": 0.15,
            "value": 0.95,
            "requires": {"capabilities_any": ["shell"], "capabilities_all": []},
            "chain": {
                "consumes_capabilities": ["shell"],
                "produces_capabilities": [],
            },
        },
    }

    show_checklist = OptBool(
        False,
        "Print manual verification checklist after the audit",
        required=False,
    )

    def _audit_script(self) -> str:
        return rf"""
$ErrorActionPreference = 'SilentlyContinue'
$fixedEngine = '{_FIXED_ENGINE}'
$fixedPlatform = '{_FIXED_PLATFORM}'

function Compare-Version([string]$a, [string]$b) {{
    if ([string]::IsNullOrWhiteSpace($a) -or [string]::IsNullOrWhiteSpace($b)) {{
        return $null
    }}
    try {{
        $va = [version](($a -split '[^0-9.]+')[0])
        $vb = [version](($b -split '[^0-9.]+')[0])
        if ($va -lt $vb) {{ return -1 }}
        if ($va -gt $vb) {{ return 1 }}
        return 0
    }} catch {{
        return $null
    }}
}}

$out = New-Object System.Collections.Generic.List[string]
$out.Add('=== Microsoft Defender CVE version audit ===')
$out.Add("Fixed floors: AMEngineVersion >= $fixedEngine (CVE-2026-41091)")
$out.Add("              AMProductVersion >= $fixedPlatform (CVE-2026-45498)")
$out.Add('')

try {{
    $st = Get-MpComputerStatus
}} catch {{
    $out.Add('ERROR: Get-MpComputerStatus unavailable: ' + $_.Exception.Message)
    $out -join "`n"
    return
}}

if (-not $st) {{
    $out.Add('ERROR: Get-MpComputerStatus returned no data (Defender cmdlets missing?)')
    $out -join "`n"
    return
}}

$engine = [string]$st.AMEngineVersion
$product = [string]$st.AMProductVersion
$rtp = $st.RealTimeProtectionEnabled
$av = $st.AntivirusEnabled
$ams = $st.AMServiceEnabled

$out.Add("AMEngineVersion     : $engine")
$out.Add("AMProductVersion    : $product")
$out.Add("AntivirusEnabled    : $av")
$out.Add("AMServiceEnabled    : $ams")
$out.Add("RealTimeProtection  : $rtp")
$out.Add('')

$cmpE = Compare-Version $engine $fixedEngine
if ($cmpE -eq $null) {{
    $out.Add('CVE-2026-41091 (LPE): UNKNOWN — could not parse AMEngineVersion')
}} elseif ($cmpE -lt 0) {{
    $out.Add("CVE-2026-41091 (LPE): VULNERABLE — engine $engine < $fixedEngine")
}} else {{
    $out.Add("CVE-2026-41091 (LPE): PATCHED — engine $engine >= $fixedEngine")
}}

$cmpP = Compare-Version $product $fixedPlatform
if ($cmpP -eq $null) {{
    $out.Add('CVE-2026-45498 (DoS): UNKNOWN — could not parse AMProductVersion')
}} elseif ($cmpP -lt 0) {{
    $out.Add("CVE-2026-45498 (DoS): VULNERABLE — platform $product < $fixedPlatform")
}} else {{
    $out.Add("CVE-2026-45498 (DoS): PATCHED — platform $product >= $fixedPlatform")
}}

$out.Add('')
$procs = Get-Process -ErrorAction SilentlyContinue |
    Where-Object {{ $_.ProcessName -match '^(MsMpEng|NisSrv|Sense)$' }}
if ($procs) {{
    $out.Add('Defender-related processes:')
    foreach ($p in $procs) {{
        $out.Add(("  {0} PID={1}" -f $p.ProcessName, $p.Id))
    }}
}} else {{
    $out.Add('Defender-related processes: none matched (MsMpEng/NisSrv/Sense)')
}}

$out -join "`n"
"""

    def _print_checklist(self) -> None:
        print_info("Manual checklist:")
        print_info("  [ ] Real-time protection enabled?")
        print_info(f"  [ ] AMEngineVersion < {_FIXED_ENGINE}? (CVE-2026-41091 LPE)")
        print_info(f"  [ ] AMProductVersion < {_FIXED_PLATFORM}? (CVE-2026-45498 DoS)")
        print_info("  [ ] MsMpEng.exe running as SYSTEM?")
        print_info("  [ ] CISA KEV: actively exploited — prioritize engine/platform update")

    def run(self):
        if not self.win_require_windows():
            return False
        if not self.win_require_powershell():
            return False

        print_status(
            "Auditing Defender versions for CVE-2026-41091 / CVE-2026-45498 "
            f"(floors {_FIXED_ENGINE} / {_FIXED_PLATFORM})"
        )
        report = self.win_run_powershell(self._audit_script(), timeout=25)
        if not report or not report.strip():
            print_error("No data returned — Defender PowerShell module may be absent")
            return False

        vulnerable = False
        for line in report.splitlines():
            text = line.rstrip()
            upper = text.upper()
            if "VULNERABLE" in upper:
                print_warning(text)
                vulnerable = True
            elif "PATCHED" in upper:
                print_success(text)
            elif "ERROR:" in upper or "UNKNOWN" in upper:
                print_error(text) if "ERROR:" in upper else print_warning(text)
            elif text.strip():
                print_info(text)

        if vulnerable:
            print_warning(
                "Host may be vulnerable — update Malware Protection Engine / "
                "Antimalware Platform (or full Windows Update)"
            )
        else:
            print_success("No vulnerable version markers detected in this audit")

        if self.show_checklist:
            self._print_checklist()

        return True
