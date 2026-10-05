#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect Cisco IOS/IOS-XE SNMP RCE surface (CVE-2025-20352)."""

from kittysploit import *
from lib.protocols.snmp.snmp_client import SNMPClient, PYSNMP_HLAPI_AVAILABLE


class Module(Scanner):
    __info__ = {
        'name': 'Cisco IOS SNMP CVE-2025-20352 Detection',
        'description': (
            'Detects Cisco IOS/IOS-XE devices with SNMP exposed that may be '
            'vulnerable to CVE-2025-20352 (stack-based buffer overflow in SNMP '
            'subsystem leading to unauthenticated RCE).'
        ),
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'cve': 'CVE-2025-20352',
        'references': [
            'https://nvd.nist.gov/vuln/detail/CVE-2025-20352',
            'https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-snmp-x-9OOGSPC',
        ],
        'tags': ['network', 'scanner', 'cisco', 'ios', 'snmp', 'rce', 'kev'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 3,
            'reversible': True,
            'approval_required': False,
            'produces': ['tech_hints', 'risk_signals'],
            'chain': {
                'suggested_followups': ['exploits/multi/udp/cisco_ios_snmp_cve_2025_20352_rce'],
            },
        },
    }

    target = OptString('', 'Target IP or hostname', required=True)
    port = OptPort(161, 'SNMP UDP port', required=True)
    community = OptString('public', 'SNMP community string', required=False)

    CISCO_OIDS = (
        '1.3.6.1.4.1.9.9.41.1.2.1.1.5',
        '1.3.6.1.4.1.9.9.46.1.6.1.1.1',
    )

    def run(self):
        if not PYSNMP_HLAPI_AVAILABLE:
            self.set_info(reason='pysnmp not installed — SNMP detection unavailable', confidence='low')
            return False
        host = str(self.target or self.rhost or '').strip()
        if not host:
            return False
        client = SNMPClient(
            host=host,
            port=int(self.port or 161),
            community=str(self.community or 'public'),
        )
        sys_desc = client.get('1.3.6.1.2.1.1.1.0')
        if not sys_desc:
            return False
        desc = str(sys_desc).lower()
        if not any(m in desc for m in ('cisco ios', 'ios-xe', 'catalyst', 'cisco')):
            return False
        for oid in self.CISCO_OIDS:
            val = client.get(oid)
            if val is not None:
                self.set_info(
                    severity='critical',
                    reason=f'Cisco IOS SNMP subsystem responsive (CVE-2025-20352 surface)',
                    cve='CVE-2025-20352',
                    sys_desc=str(sys_desc)[:200],
                    oid=oid,
                )
                return True
        if 'cisco' in desc:
            self.set_info(
                severity='high',
                reason='Cisco device with SNMP enabled — verify CVE-2025-20352 patch level',
                cve='CVE-2025-20352',
                sys_desc=str(sys_desc)[:200],
            )
            return True
        return False
