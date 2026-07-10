#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.ldap.ad_client import Ad_client, LDAP3_AVAILABLE
from lib.protocols.smb.relay_audit import audit_smb_relay_surface
from lib.protocols.smb.smb_exec import impacket_available


class Module(Scanner, Http_client, Ad_client):

    __info__ = {
        "name": "CVE-2026-26128 Windows SMB improper authentication detection",
        "description": (
            "CVE-2026-26128: improper authentication in Windows SMB Server allows an "
            "authorized attacker to elevate privileges locally. Detects exposure factors "
            "for SMB improper-authentication privesc abuse: LDAP/ADIDNS reachability, AD CS "
            "HTTP enrollment, and SMB signing posture on coercion targets."
        ),
        "author": ["Guillaume André / Synacktiv", "KittySploit Team"],
        "severity": "critical",
        "cve": "CVE-2026-26128",
        "references": [
            "https://www.cve.org/CVERecord?id=CVE-2026-26128",
            "https://synacktiv.com/publications/bypassing-windows-authentication-reflection-mitigations-for-system-shells-part",
        ],
        "modules": [
            "exploits/multi/windows/cve_2026_26128_smb_improper_auth",
            "auxiliary/admin/ldap/ad_idns_record",
        ],
        "tags": [
            "ad",
            "kerberos",
            "dns",
            "ssrf",
            "relay",
            "adcs",
            "mssql",
            "smb",
            "privesc",
            "cve-2026-26128",
            "scanner",
        ],
    }

    port = OptPort(443, "HTTPS port for AD CS checks", required=True)
    ssl = OptBool(True, "Use HTTPS for AD CS checks", required=True)
    smb_port = OptPort(445, "SMB port for signing audit", required=False)
    check_adcs = OptBool(True, "Probe AD CS /certsrv enrollment surface", required=False)
    check_smb = OptBool(True, "Audit SMB signing on the target host", required=False)

    def _adcs_detected(self) -> bool:
        if not self.check_adcs:
            return False
        for path in ("/certsrv/", "/certsrv/certfnsh.asp", "/CertEnroll/"):
            response = self.http_request(method="GET", path=path, allow_redirects=False, timeout=8)
            if not response or response.status_code not in (200, 302, 401):
                continue
            body = (response.text or "").lower()
            if "certsrv" in body or "certificate services" in body or response.status_code == 401:
                return True
        return False

    def run(self):
        try:
            signals = []
            severity = "medium"

            if LDAP3_AVAILABLE and self.conn:
                signals.append("LDAP bind OK (ADIDNS record management likely available)")
            else:
                signals.append("LDAP bind failed or ldap3 unavailable")

            if self._adcs_detected():
                signals.append("AD CS HTTP enrollment surface detected")
                severity = "high"

            if self.check_smb:
                host = str(self.target or "").strip()
                audit = audit_smb_relay_surface(host, int(self.smb_port or 445), timeout=5.0)
                signing = audit.get("signing_status")
                signals.append(f"SMB signing status: {signing}")
                if signing in ("disabled", "enabled_not_required"):
                    severity = "critical"

            if pysmb_available():
                signals.append("pysmb available for native coercion (no impacket)")
            else:
                signals.append("pysmb not installed (required for coercion)")

            relay_target = str(getattr(self, "relay_target", "") or "").lower()
            if relay_target and ("certsrv" in relay_target or relay_target.startswith("mssql://")):
                signals.append("Relay target supports native stack without impacket")
            elif impacket_available():
                signals.append("impacket available for legacy relay backends")
            else:
                signals.append("impacket not installed (only needed for non-native relay targets)")

            if not signals:
                return False

            self.set_info(
                severity=severity,
                cve="CVE-2026-26128",
                reason="; ".join(signals),
                impacket_available=impacket_available(),
            )
            return True
        except Exception as exc:
            print_error(f"Scanner failed: {exc}")
            return False
