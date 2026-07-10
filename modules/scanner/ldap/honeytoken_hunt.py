#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Repérage de honeytokens AD via l'oracle lastLogon (historique comportemental).

Préférer le module SMB (SAMR, port 445) : scanner/smb/honeytoken_hunt
Ce module LDAP reste un repli quand seul le bind directory est disponible.
"""

from kittysploit import *
from lib.protocols.ldap.ad_client import Ad_client
from lib.protocols.ldap.honeytoken import (
    PROBABLE_THRESHOLD,
    SUSPICIOUS_THRESHOLD,
    assess_ldap_entry,
    assessments_to_guardian_payload,
)

_BEHAVIOUR_ATTRS = [
    "sAMAccountName",
    "lastLogon",
    "logonCount",
    "adminCount",
    "pwdLastSet",
    "description",
    "userAccountControl",
]


class Module(Scanner, Ad_client):
    __info__ = {
        "name": "AD honeytoken hunt (lastLogon oracle)",
        "description": (
            "Flags probable AD honeytokens/decoys via empty auth history "
            "(lastLogon=0, logonCount=0) and feeds Guardian."
        ),
        "author": "KittySploit Team",
        "severity": "medium",
        "modules": [],
        "tags": ["ad", "ldap", "scanner", "honeypot", "honeytoken", "guardian"],
    'agent': {
        'risk': 'active',
        'effects': ['network_probe'],
        'expected_requests': 2,
        'reversible': True,
        'approval_required': False,
        'produces': ['tech_hints', 'risk_signals', 'endpoints'],
        'cost': 1.0,
        'noise': 0.5,
        'value': 1.0,
        'requires':         {'min_endpoints': 0,
         'min_params': 0,
         'tech_hints_any': [],
         'tech_hints_all': [],
         'specializations_any': [],
         'risk_signals_any': [],
         'auth_session': False,
         'capabilities_any': [],
         'capabilities_all': [],
         'confidence_min': {},
         'confidence_min_any': {},
         'endpoint_pattern_any': [],
         'param_any': [],
         'api_surface_ready': False},
        'chain':         {'produces_capabilities': [{'capability': 'ssrf_primitive', 'from_detail': ''},
                                   {'capability': 'file_read', 'from_detail': 'lfi_path'},
                                   {'capability': 'lfi_param', 'from_detail': 'lfi_param'},
                                   {'capability': 'file_read', 'from_detail': 'lfi_path'},
                                   {'capability': 'lfi_param', 'from_detail': 'lfi_param'},
                                   {'capability': 'file_read', 'from_detail': 'lfi_path'},
                                   {'capability': 'lfi_param', 'from_detail': 'lfi_param'},
                                   {'capability': 'ssrf_primitive', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'file_read', 'from_detail': 'lfi_path'},
                                   {'capability': 'lfi_param', 'from_detail': 'lfi_param'},
                                   {'capability': 's7comm', 'from_detail': ''},
                                   {'capability': 's7comm', 'from_detail': ''},
                                   {'capability': 's7comm', 'from_detail': ''}],
         'consumes_capabilities': [],
         'option_bindings': {},
         'suggested_followups': []},
    },
    }

    min_score = OptFloat(
        SUSPICIOUS_THRESHOLD,
        "Minimum Guardian score to report (0-100)",
        False,
        advanced=True,
    )
    users = OptBool(True, "Evaluate user accounts", False, advanced=True)
    computers = OptBool(True, "Evaluate computer accounts ($)", False, advanced=True)
    auto_blacklist = OptBool(
        True,
        "Register probable honeytokens with Guardian when enabled",
        False,
        advanced=True,
    )

    def run(self):
        if not self.base_dn:
            print_warning("LDAP bind failed or base DN unavailable")
            return False

        min_score = float(getattr(self.min_score, "value", SUSPICIOUS_THRESHOLD) or 0)
        scan_users = bool(getattr(self.users, "value", True))
        scan_computers = bool(getattr(self.computers, "value", True))
        feed_guardian = bool(getattr(self.auto_blacklist, "value", True))

        assessments = []

        if scan_users:
            users = self.search(
                "(&(objectCategory=person)(objectClass=user)(!(objectClass=computer)))",
                _BEHAVIOUR_ATTRS,
            )
            for entry in users:
                item = assess_ldap_entry(entry)
                if item and item.score >= min_score:
                    assessments.append(item)

        if scan_computers:
            computers = self.search(
                "(objectClass=computer)",
                _BEHAVIOUR_ATTRS + ["operatingSystem"],
            )
            for entry in computers:
                item = assess_ldap_entry(entry)
                if item and item.score >= min_score:
                    assessments.append(item)

        if not assessments:
            print_info("No AD accounts matched honeytoken behavioural criteria")
            return False

        assessments.sort(key=lambda a: (-a.score, a.sam_account.lower()))
        probable = [a for a in assessments if a.score >= PROBABLE_THRESHOLD]
        suspicious = [
            a
            for a in assessments
            if SUSPICIOUS_THRESHOLD <= a.score < PROBABLE_THRESHOLD
        ]

        domain = self.domain or self.base_dn
        print_warning(
            f"Honeytoken hunt: {len(probable)} probable, {len(suspicious)} suspicious "
            f"(min score {min_score:.0f})"
        )

        for item in assessments[:40]:
            tag = item.verdict
            detail = "; ".join(item.signals[:3])
            print_info(f"  [{tag}] {item.sam_account} ({item.score:.0f}%) — {detail}")

        if len(assessments) > 40:
            print_info(f"  … and {len(assessments) - 40} more")

        if feed_guardian:
            gm = getattr(self.framework, "guardian_manager", None)
            if gm:
                payload = assessments_to_guardian_payload(domain, assessments, source="ldap")
                registered = gm.register_identity_assessments(payload)
                print_success(
                    f"Guardian: {registered} identity profile(s) updated "
                    f"({len(probable)} probable honeytoken(s))"
                )
            else:
                print_warning("Guardian manager unavailable — findings not persisted")

        reason = (
            f"{len(probable)} probable honeytoken(s), {len(suspicious)} suspicious; "
            f"top: {', '.join(a.sam_account for a in probable[:5])}"
        )
        self.set_info(
            severity="high" if probable else "medium",
            reason=reason,
            probable_count=len(probable),
            suspicious_count=len(suspicious),
        )
        return True
