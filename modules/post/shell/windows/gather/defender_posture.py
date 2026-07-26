#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *

from lib.post.windows.session import WindowsSessionMixin


class Module(Post, WindowsSessionMixin):
    __info__ = {
        "name": "Windows Gather Defender Posture Audit",
        "description": "Audit Defender status, preferences, and recent detections",
        "author": "KittySploit Team",
        "platform": Platform.WINDOWS,
        "session_type": [SessionType.METERPRETER, SessionType.SHELL],
        "references": [
            "https://attack.mitre.org/techniques/T1518.001/",
            "https://attack.mitre.org/techniques/T1562/001/",
        ],
        "agent": {
            "risk": "passive",
            "effects": ["reconnaissance"],
            "expected_requests": 3,
            "reversible": True,
            "approval_required": False,
            "produces": ["risk_signals"],
            "cost": 0.5,
            "noise": 0.2,
            "value": 0.9,
            "requires": {"capabilities_any": ["shell"], "capabilities_all": []},
            "chain": {
                "consumes_capabilities": ["shell"],
                "produces_capabilities": [],
            },
        },
    }

    include_threat_intel = OptBool(True, "Include recent Defender threat detections", False)

    def _status_script(self) -> str:
        return r"""
$ErrorActionPreference = 'SilentlyContinue'
try {
    $status = Get-MpComputerStatus
    if ($status) {
        $status | Select-Object `
            AMServiceEnabled, AntivirusEnabled, AntispywareEnabled,
            RealTimeProtectionEnabled, OnAccessProtectionEnabled, IoavProtectionEnabled,
            BehaviorMonitorEnabled, AntivirusSignatureLastUpdated,
            AntivirusSignatureAge, AntispywareSignatureAge,
            QuickScanAge, FullScanAge, NISEnabled, IsTamperProtected,
            IsVirtualMachine, ComputerState, FullScanEndTime, QuickScanEndTime |
            Format-List | Out-String -Width 4096
    } else {
        'Get-MpComputerStatus returned no data'
    }
} catch {
    'Get-MpComputerStatus unavailable: ' + $_.Exception.Message
}
"""

    def _preference_script(self) -> str:
        return r"""
$ErrorActionPreference = 'SilentlyContinue'
try {
    $pref = Get-MpPreference
    if ($pref) {
        [PSCustomObject]@{
            DisableRealtimeMonitoring = $pref.DisableRealtimeMonitoring
            DisableBehaviorMonitoring = $pref.DisableBehaviorMonitoring
            DisableIOAVProtection = $pref.DisableIOAVProtection
            DisableScriptScanning = $pref.DisableScriptScanning
            DisableArchiveScanning = $pref.DisableArchiveScanning
            DisableIntrusionPreventionSystem = $pref.DisableIntrusionPreventionSystem
            PUAProtection = $pref.PUAProtection
            MAPSReporting = $pref.MAPSReporting
            SubmitSamplesConsent = $pref.SubmitSamplesConsent
            EnableControlledFolderAccess = $pref.EnableControlledFolderAccess
            AttackSurfaceReductionRules_Ids = $pref.AttackSurfaceReductionRules_Ids
            AttackSurfaceReductionOnlyExclusions = $pref.AttackSurfaceReductionOnlyExclusions
            ExclusionPath = $pref.ExclusionPath
            ExclusionExtension = $pref.ExclusionExtension
            ExclusionProcess = $pref.ExclusionProcess
            ExclusionIpAddress = $pref.ExclusionIpAddress
            ControlledFolderAccessProtectedFolders = $pref.ControlledFolderAccessProtectedFolders
            ControlledFolderAccessAllowedApplications = $pref.ControlledFolderAccessAllowedApplications
        } | Format-List | Out-String -Width 4096
    } else {
        'Get-MpPreference returned no data'
    }
} catch {
    'Get-MpPreference unavailable: ' + $_.Exception.Message
}
"""

    def _threat_script(self) -> str:
        return r"""
$ErrorActionPreference = 'SilentlyContinue'
try {
    $threats = Get-MpThreatDetection -ErrorAction SilentlyContinue |
        Select-Object -First 15 ThreatName, InitialDetectionTime, Resources, ActionSuccess
    if ($threats) {
        ($threats | Format-Table -AutoSize | Out-String).Trim()
    } else {
        'No recent threat detections returned by Get-MpThreatDetection'
    }
} catch {
    'Get-MpThreatDetection unavailable: ' + $_.Exception.Message
}
"""

    def run(self):
        if not self.win_require_windows():
            return False
        if not self.win_require_powershell():
            return False

        print_info("=" * 60)
        print_info("Microsoft Defender")

        print_info("-" * 60)
        print_info("Computer status (Get-MpComputerStatus)")
        status = self.win_run_powershell(self._status_script(), timeout=25)
        print_info(status or "(no data — Defender cmdlets may be absent)")

        print_info("-" * 60)
        print_info("Preferences (Get-MpPreference)")
        prefs = self.win_run_powershell(self._preference_script(), timeout=25)
        print_info(prefs or "(no data)")

        if self.include_threat_intel:
            print_info("-" * 60)
            print_info("Recent threat detections")
            threats = self.win_run_powershell(self._threat_script(), timeout=20)
            print_info(threats or "(no data)")

        print_info("=" * 60)
        return True
