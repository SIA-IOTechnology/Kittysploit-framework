#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Détection interfaces de gestion télécom (eNodeB/gNodeB, OSS, équipementiers)."""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):

    __info__ = {
        "name": "Telecom management interface detection",
        "description": "Detects telecom / 5G management UIs (eNodeB, gNodeB, OSS, vendor panels).",
        "author": "KittySploit Team",
        "severity": "medium",
        "modules": [],
        "tags": ["telecom", "scanner", "5g", "lte", "management", "oss", "ran", "huawei", "ericsson", "nokia"],
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

    # Mots longs / phrases : sous-chaîne OK (peu de collisions)
    _PHRASES = (
        "element manager",
        "network manager",
        "radio access",
        "core network",
        "5gc",
    )

    # Mots courts ou ambigus : mot entier uniquement (\b) pour éviter "ran" dans "random", "oss" dans "gossip", etc.
    _WORD_PATTERNS = (
        (r"\bhuawei\b", "huawei"),
        (r"\bericsson\b", "ericsson"),
        (r"\bnokia\b", "nokia"),
        (r"\bzte\b", "zte"),
        (r"\bsamsung\b", "samsung"),
        (r"\bcisco\b", "cisco"),
        (r"\benodeb\b", "enodeb"),
        (r"\bgnodeb\b", "gnodeb"),
        (r"\benb\b", "enb"),
        (r"\bgnb\b", "gnb"),
        (r"\bran\b", "ran"),
        (r"\blte\b", "lte"),
        (r"\b5g\b", "5g"),
        (r"\bnr\b", "nr"),
        (r"\boss\b", "oss"),
        (r"\bbsc\b", "bsc"),
        (r"\brnc\b", "rnc"),
        (r"\bmme\b", "mme"),
        (r"\bhss\b", "hss"),
        (r"\bepc\b", "epc"),
    )

    def run(self):
        r = self.http_request(method="GET", path="/", allow_redirects=True)
        if not r:
            return False
        t = r.text.lower()

        for phrase in self._PHRASES:
            if phrase in t:
                self.set_info(severity="medium", reason=f"Telecom/5G management phrase: {phrase}")
                return True

        for rx, label in self._WORD_PATTERNS:
            if re.search(rx, t, re.IGNORECASE):
                self.set_info(severity="medium", reason=f"Telecom/5G management keyword: {label}")
                return True

        for path in ["/admin", "/webui", "/oss", "/omc"]:
            r2 = self.http_request(method="GET", path=path, allow_redirects=False)
            if r2 and r2.status_code == 200 and len(r2.text) > 100:
                low = r2.text.lower()
                if any(
                    re.search(p, low, re.IGNORECASE)
                    for p in (r"\blogin\b", r"\bpassword\b", r"\badmin\b", r"\blte\b", r"\b5g\b", r"\bradio\b")
                ):
                    self.set_info(severity="medium", reason=f"Management-like path: {path}")
                    return True
        return False
