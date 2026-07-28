#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Finds friendly path exposed that can be used to access signup page and create new user accounts."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'IBM Websphere Friendly Path Exposure Detection',
        'description': 'Finds friendly path exposed that can be used to access signup page and create new user accounts.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'misconfiguration', 'ibm', 'exposure', 'websphere', 'misconfig', 'vuln'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 5,
            'reversible': True,
            'approval_required': False,
            'produces': ['tech_hints', 'risk_signals', 'endpoints'],
            'cost': 1.0,
            'noise': 0.3,
            'value': 1.0,
            'requires': {
                'min_endpoints': 0,
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
                'api_surface_ready': False,
            },
            'chain': {
                'produces_capabilities': [
                    {
                        'capability': 'admin_surface',
                        'from_detail': '',
                    },
                ],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': ['auxiliary/scanner/http/login_page_detector'],
            },
        },
        'references': ['https://clarkvoss.medium.com/how-to-harpon-big-blue-c163722638d8'],
    }

    def run(self):
        for path in ('/wps/portal/client/welcome/!ut/p/z1/04_Sj9CPykssy0xPLMnMz0vMAfIjo8ziHd3DQgMNnM3N_M1DjA08PX0NgoNcnQwt3Ez1wwkpiAJKG-AAjgb6BbmhigBypoQ7/dz/d5/L2dBISEvZ0FBIS9nQSEh/?uri=nm:oid:Z6_00000000000000A0BR2B300GG2', '/wps/portal/!ut/p/z1/04_Sj9CPykssy0xPLMnMz0vMAfIjo8ziHd3DQgMNnM3N_M1DjA08PX0NgoNcnQwt3Ez1wwkpiAJKG-AAjgb6BbmhigBypoQ7/dz/d5/L2dBISEvZ0FBIS9nQSEh/?uri=nm:oid:Z6_00000000000000A0BR2B300GG2', '/wps/portal/!ut/p/z1/04_Sj9CPykssy0xPLMnMz0vMAfIjo8ziDVCAo4FTkJGTsYGBu7uRfjhYgaN7WGiggbO5mb95iLGBp6evQXCQq5OhhZupfhSGfmSToPrxWEBQfxRYSYCHh5mHoYWBj7-RL1DC1y3M2NXCx9jA3RiqAI8ZBbmhEQaZjooABQv7ag!!/dz/d5/L2dBISEvZ0FBIS9nQSEh/dz/d5/L0lJSkdKSUtVSklKQ2dwUkNncFJBL29Od3dBQUFZUUFBRUl3UWxDVTVBQUdNSUtTcEtGTFJ0R0ZvIS80TmxFTklVTVFuRmR1WXBNaFFUVWs1Q2ltcHBBL1o2XzAwMDAwMDAwMDAwMDAwQTBCUjJCMzAwR1YwL1o3XzAwMDAwMDAwMDAwMDAwQTBCUjJCMzAwSU8wL25vcm1hbC9PQ04vWjZfMDAwMDAwMDAwMDAwMDBBMEJSMkIzMDBHRzIvYW8vdGht/#Z7_00000000000000A0BR2B300IO0', '/wps/portal/!ut/p/z1/04_Sj9CPykssy0xPLMnMz0vMAfIjo8ziDVCAo4FTkJGTsYGBu7uRfjhYgaN7WGiggbO5mb95iLGBp6evQXCQq5OhhZupfhSGfmSToPrxWEBAf0FuaCgAb7VcBA!!/dz/d5/L2dBISEvZ0FBIS9nQSEh/dz/d5/L0lJSkdKSUtVSklKQ2dwUkNncFJBL29Od3dBQUFZUUFBRUl3UWxDVTVBQUdNSUtTcEtGTFJ0R0ZvIS80TmxFTklVTVFuRmR1WXBNaFFUVWs1Q2ltcHBBL1o2XzAwMDAwMDAwMDAwMDAwQTBCUjJCMzAwR1YwL1o3XzAwMDAwMDAwMDAwMDAwQTBCUjJCMzAwSU8wL25vcm1hbC9PQ04vWjZfMDAwMDAwMDAwMDAwMDBBMEJSMkIzMDBHRzIvYW8vdGht/#Z7_00000000000000A0BR2B300IO0', '/wps/portal/!ut/p/z1/pZHBDoIwDIYfqZVF4DoIEg5KBEHWi9mBIAnbjCEefHqH8SARJNGe2qRf_78tEFRAWt7aRvat0bKztSD3hKPgGGROwBDjEuH4bOBxWewx9NzUOzBMki3mWRSs_M0a6IN_n_Ti5wRiZ4Kf0J9r8PEXfmTwL_0Sl_YXlvfm-CRFKLS5KvuJHAgoDXeL9wKSBkR_VkPa6QZEra1N-rrJcKglqxdV2KjuEVM-czP-AKyJL-g!/dz/d5/L2dBISEvZ0FBIS9nQSEh/#Z7_00000000000000A0BR2B300IO0'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
            body_any = ('Friendly path', 'IBM WebSphere Portal',)
            header_any = ('text/html',)
            header_regexes = ('Content-Location: .+',)
            if (any(m in body for m in body_any)) and (any(m in headers for m in header_any)) and (any(re.search(rx, headers, 0) for rx in header_regexes)):
                self.set_info(
                    severity='medium',
                    reason="IBM Websphere Friendly Path Exposure detected",
                    path=path,
                )
                return True
        return False

