#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Chasse aux honeytokens AD via SAMR / NetUserEnum (port 445, sans LDAP ni Impacket).

Collecte lastLogon et logonCount dans le trafic SAM habituel — signal faible pour
les défenseurs, oracle fort pour repérer les comptes jamais authentifiés.
"""

from kittysploit import *
from lib.protocols.ldap.honeytoken import (
    PROBABLE_THRESHOLD,
    SUSPICIOUS_THRESHOLD,
    assess_sam_record,
    assessments_to_guardian_payload,
)
from lib.protocols.samr import SamEnumerationError, SamEnumerator
from lib.protocols.smb.smb_scanner_client import Smb_scanner_client


class Module(Scanner, Smb_scanner_client):
    __info__ = {
        "name": "AD honeytoken hunt (SAMR lastLogon oracle)",
        "description": (
            "Enumerates AD accounts via native SAMR/NetAPI (port 445) and flags "
            "probable honeytokens from empty auth history; feeds Guardian."
        ),
        "author": "KittySploit Team",
        "severity": "medium",
        "modules": [],
        "tags": ["ad", "smb", "samr", "scanner", "honeypot", "honeytoken", "guardian"],
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
                                   {'capability': 's7comm', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''}],
         'consumes_capabilities': [],
         'option_bindings': {},
         'suggested_followups': []},
    },
    }

    username = OptString("", "Domain user (DOMAIN\\user or user@domain)", False)
    password = OptString("", "Password", False)
    domain = OptString("", "AD domain (optional if included in username)", False)
    min_score = OptFloat(
        SUSPICIOUS_THRESHOLD,
        "Minimum score to report (0-100)",
        False,
        advanced=True,
    )
    users = OptBool(True, "Evaluate user accounts", False, advanced=True)
    computers = OptBool(True, "Evaluate computer accounts ($)", False, advanced=True)
    prefer_samr = OptBool(
        False,
        "Force SAMR RPC even on Windows (skip NetUserEnum)",
        False,
        advanced=True,
    )
    auto_blacklist = OptBool(
        True,
        "Register probable honeytokens with Guardian when enabled",
        False,
        advanced=True,
    )

    def _parse_credentials(self):
        user = (getattr(self.username, "value", "") or "").strip()
        pwd = getattr(self.password, "value", "") or ""
        dom = (getattr(self.domain, "value", "") or "").strip()

        if "@" in user and not dom:
            dom = user.split("@", 1)[1]
        elif "\\" in user:
            dom, user = user.split("\\", 1)

        return user, pwd, dom

    def run(self):
        host = self._host()
        if not host:
            print_warning("Target host is required")
            return False

        user, pwd, dom = self._parse_credentials()
        min_score = float(getattr(self.min_score, "value", SUSPICIOUS_THRESHOLD) or 0)
        scan_users = bool(getattr(self.users, "value", True))
        scan_computers = bool(getattr(self.computers, "value", True))
        feed_guardian = bool(getattr(self.auto_blacklist, "value", True))
        force_samr = bool(getattr(self.prefer_samr, "value", False))

        print_info(f"SAM honeytoken hunt on {host}:445 (no LDAP bind)")

        try:
            enumerator = SamEnumerator(
                host=host,
                port=self._port(),
                username=user,
                password=pwd,
                domain=dom,
                remote_name=host,
                timeout=int(self._timeout()),
                prefer_samr=force_samr,
            )
            records = enumerator.enumerate(
                include_users=scan_users,
                include_computers=scan_computers,
            )
        except SamEnumerationError as exc:
            print_error(str(exc))
            return False

        assessments = []
        for record in records:
            item = assess_sam_record(record)
            if item and item.score >= min_score:
                assessments.append(item)

        if not assessments:
            print_info(
                f"No honeytoken candidates in {len(records)} SAM account(s) "
                f"(min score {min_score:.0f})"
            )
            return False

        assessments.sort(key=lambda a: (-a.score, a.sam_account.lower()))
        probable = [a for a in assessments if a.score >= PROBABLE_THRESHOLD]
        suspicious = [
            a
            for a in assessments
            if SUSPICIOUS_THRESHOLD <= a.score < PROBABLE_THRESHOLD
        ]

        domain_label = dom or host
        print_warning(
            f"SAM oracle: {len(probable)} probable, {len(suspicious)} suspicious "
            f"({len(records)} accounts scanned)"
        )

        for item in assessments[:40]:
            detail = "; ".join(item.signals[:3])
            print_info(f"  [{item.verdict}] {item.sam_account} ({item.score:.0f}%) — {detail}")

        if len(assessments) > 40:
            print_info(f"  … and {len(assessments) - 40} more")

        if feed_guardian:
            gm = getattr(self.framework, "guardian_manager", None)
            if gm:
                payload = assessments_to_guardian_payload(
                    domain_label,
                    assessments,
                    source="samr",
                )
                registered = gm.register_identity_assessments(payload)
                print_success(
                    f"Guardian: {registered} identity profile(s) updated "
                    f"({len(probable)} probable honeytoken(s))"
                )
            else:
                print_warning("Guardian manager unavailable — findings not persisted")

        self.set_info(
            severity="high" if probable else "medium",
            reason=(
                f"{len(probable)} probable honeytoken(s), {len(suspicious)} suspicious; "
                f"top: {', '.join(a.sam_account for a in probable[:5])}"
            ),
            probable_count=len(probable),
            suspicious_count=len(suspicious),
            accounts_scanned=len(records),
        )
        return True
