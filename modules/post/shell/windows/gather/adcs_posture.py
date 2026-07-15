#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json

from kittysploit import *

from lib.post.windows.session import WindowsSessionMixin


class Module(Post, WindowsSessionMixin):
    __info__ = {
        "name": "Windows Gather ADCS Posture Audit",
        "description": "Discover AD CS endpoints and risky certificate templates",
        "author": "KittySploit Team",
        "platform": Platform.WINDOWS,
        "session_type": [SessionType.METERPRETER, SessionType.SHELL],
        "references": [
            "https://attack.mitre.org/techniques/T1649/",
            "https://posts.specterops.io/certified-pre-owned-d95910965cd2",
        ],
        "agent": {
            "risk": "passive",
            "effects": ["reconnaissance"],
            "expected_requests": 4,
            "reversible": True,
            "approval_required": False,
            "produces": ["risk_signals"],
            "cost": 0.6,
            "noise": 0.25,
            "value": 0.95,
            "requires": {"capabilities_any": ["shell"], "capabilities_all": []},
            "chain": {
                "consumes_capabilities": ["shell"],
                "produces_capabilities": [],
            },
        },
    }

    max_templates = OptInteger(40, "Maximum certificate templates to analyze", False)

    def _collect_script(self) -> str:
        max_templates = int(self.max_templates or 40)
        return rf"""
$ErrorActionPreference = 'SilentlyContinue'
$maxTemplates = {max_templates}

function Get-ClientAuthOid {{
    return '1.3.6.1.5.5.7.3.2'
}}

function Test-TemplateRisk($entry) {{
    $flags = 0
    if ($entry.Properties['msPKI-Certificate-Name-Flag']) {{
        $flags = [int]$entry.Properties['msPKI-Certificate-Name-Flag'].Value
    }}
    $enrolleeSupplies = ($flags -band 1) -eq 1
    $eku = @()
    if ($entry.Properties['pKIExtendedKeyUsage']) {{
        $eku = @($entry.Properties['pKIExtendedKeyUsage']) | ForEach-Object {{ $_.Value }}
    }}
    $clientAuth = $eku -contains (Get-ClientAuthOid)
    $noManager = $true
    if ($entry.Properties['msPKI-Enrollment-Flag']) {{
        $ef = [int]$entry.Properties['msPKI-Enrollment-Flag'].Value
        $noManager = ($ef -band 32) -eq 0
    }}
    $enabled = $true
    if ($entry.Properties['flags']) {{
        $enabled = ([int]$entry.Properties['flags'].Value -band 2) -eq 0
    }}
    $risk = @()
    if ($enabled -and $enrolleeSupplies -and $clientAuth -and $noManager) {{
        $risk += 'ESC1-indicator'
    }}
    if ($enabled -and ($eku.Count -eq 0 -or ($eku -contains '1.3.6.1.5.5.7.3.4'))) {{
        $risk += 'AnyPurpose/ESC2-indicator'
    }}
    [PSCustomObject]@{{
        Name = $entry.Properties['cn'].Value
        Enabled = $enabled
        EnrolleeSuppliesSubject = $enrolleeSupplies
        ClientAuthEKU = $clientAuth
        RequiresManagerApproval = -not $noManager
        ExtendedKeyUsage = $eku
        RiskFlags = $risk
    }}
}}

$report = [PSCustomObject]@{{
    PartOfDomain = $false
    Domain = $null
    CertSvcInstalled = $false
    CaPing = (certutil -config - -ping 2>&1 | Out-String).Trim()
    CaInfo = (certutil -TCAInfo 2>&1 | Out-String).Trim()
    EnrollmentUrls = @()
    Templates = @()
    RiskyTemplates = @()
    Errors = @()
}}

$cs = Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue
if ($cs) {{
    $report.PartOfDomain = [bool]$cs.PartOfDomain
    $report.Domain = $cs.Domain
}}

if (Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc') {{
    $report.CertSvcInstalled = $true
}}

if (-not $report.PartOfDomain) {{
    $report | ConvertTo-Json -Depth 6 -Compress
    return
}}

try {{
    Add-Type -AssemblyName System.DirectoryServices
    $rootDse = New-Object System.DirectoryServices.DirectoryEntry('LDAP://RootDSE')
    $configNc = $rootDse.Properties['configurationNamingContext'].Value
    $base = "LDAP://CN=Enrollment Services,CN=Public Key Services,CN=Services,$configNc"
    $searcher = New-Object System.DirectoryServices.DirectorySearcher
    $searcher.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry($base)
    $searcher.Filter = '(objectClass=pKIEnrollmentService)'
    $searcher.SizeLimit = 20
    $results = $searcher.FindAll()
    foreach ($r in $results) {{
        $dn = $r.Properties['distinguishedname'][0]
        $name = $r.Properties['cn'][0]
        $dns = $r.Properties['dNSHostName'][0]
        $report.EnrollmentUrls += [PSCustomObject]@{{
            Name = $name
            DnsHost = $dns
            DN = $dn
        }}
    }}
}} catch {{
    $report.Errors += 'Enrollment service LDAP query failed: ' + $_.Exception.Message
}}

try {{
    Add-Type -AssemblyName System.DirectoryServices
    $rootDse = New-Object System.DirectoryServices.DirectoryEntry('LDAP://RootDSE')
    $configNc = $rootDse.Properties['configurationNamingContext'].Value
    $base = "LDAP://CN=Certificate Templates,CN=Public Key Services,CN=Services,$configNc"
    $searcher = New-Object System.DirectoryServices.DirectorySearcher
    $searcher.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry($base)
    $searcher.Filter = '(objectClass=pKICertificateTemplate)'
    $searcher.SizeLimit = $maxTemplates
    $searcher.PropertiesToLoad.AddRange(@('cn','flags','pKIExtendedKeyUsage','msPKI-Certificate-Name-Flag','msPKI-Enrollment-Flag'))
    $results = $searcher.FindAll()
    foreach ($r in $results) {{
        $assessment = Test-TemplateRisk $r
        $report.Templates += $assessment
        if ($assessment.RiskFlags -and $assessment.RiskFlags.Count -gt 0) {{
            $report.RiskyTemplates += $assessment
        }}
    }}
}} catch {{
    $report.Errors += 'Template LDAP query failed: ' + $_.Exception.Message
}}

$report | ConvertTo-Json -Depth 8 -Compress
"""

    def run(self):
        if not self.win_require_windows():
            return False
        if not self.win_require_powershell():
            return False

        print_info("=" * 60)
        print_info("AD CS")

        raw = self.win_run_powershell(self._collect_script(), timeout=45)
        if not raw:
            print_warning("Collector returned no output")
            return False

        try:
            data = json.loads(raw.strip().splitlines()[-1])
        except Exception as exc:
            print_error(f"Failed to parse ADCS audit output: {exc}")
            print_info(raw[:3000])
            return False

        if not data.get("PartOfDomain"):
            print_status("Host is not domain-joined — ADCS template LDAP audit skipped")
            print_info("=" * 60)
            return True

        print_info(f"Domain: {data.get('Domain', '?')}")
        if data.get("CertSvcInstalled"):
            print_warning("CertSvc role detected on this host (CA server)")

        print_info("-" * 60)
        print_info("CA discovery (certutil)")
        for block, label in (
            (data.get("CaPing"), "ping"),
            (data.get("CaInfo"), "TCAInfo"),
        ):
            if block:
                print_info(f"  [{label}]")
                for line in block.splitlines()[:12]:
                    print_info(f"    {line}")

        enroll = data.get("EnrollmentUrls") or []
        print_info("-" * 60)
        print_info(f"Enrollment services (LDAP): {len(enroll)}")
        for svc in enroll[:10]:
            print_info(f"  {svc.get('Name', '?')} @ {svc.get('DnsHost', '?')}")

        risky = data.get("RiskyTemplates") or []
        templates = data.get("Templates") or []
        print_info("-" * 60)
        print_info(f"Certificate templates analyzed: {len(templates)}")
        if risky:
            print_warning(f"Risky templates flagged: {len(risky)}")
            for tmpl in risky[:15]:
                flags = ", ".join(tmpl.get("RiskFlags") or [])
                print_warning(f"  {tmpl.get('Name', '?')} — {flags}")
        else:
            print_status("No high-risk template indicators matched (ESC1/ESC2 heuristics)")

        for err in data.get("Errors") or []:
            print_warning(err)

        print_info("=" * 60)
        return True
