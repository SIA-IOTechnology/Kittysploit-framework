#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""TBK DVR4104 and DVR4216 devices, as well as Novo, CeNova, QSee, Pulnix, XVR 5 in 1, Securus, Night OWL, DVR Lo."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'TBK DVR4104/DVR4216 Devices - Authentication Bypass Detection',
        'description': 'TBK DVR4104 and DVR4216 devices, as well as Novo, CeNova, QSee, Pulnix, XVR 5 in 1, Securus, Night OWL, DVR Login, HVR Login, and MDVR Login, which run re-branded versions of the original TBK DVR4104 and DVR4216 series, allow remote attackers to bypass authentication via a "Cookie: uid=admin" header, as demonstrated by a device.rsp?opt=user&cmd=list request that provides credentials within JSON data in a response.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2018', 'auth-bypass', 'tbk', 'edb', 'tbkvision', 'vkev', 'vuln'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 1,
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
        'references': [
            'https://www.exploit-db.com/exploits/44577/',
            'http://misteralfa-hack.blogspot.cl/2018/04/tbk-vision-dvr-login-bypass.html',
            'http://misteralfa-hack.blogspot.cl/2018/04/update-dvr-login-bypass-cve-2018-9995.html',
            'https://www.bleepingcomputer.com/news/security/new-hacking-tool-lets-users-access-a-bunch-of-dvrs-and-their-video-feeds/',
            'https://nvd.nist.gov/vuln/detail/CVE-2018-9995',
        ],
        'cve': 'CVE-2018-9995',
    }

    def run(self):
        r = self.http_request(method="GET", path='/device.rsp?opt=user&cmd=list', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('"uid":', '"pwd":', '"view":', 'playback',)
        if (all(m in body for m in body_all)):
            self.set_info(
                severity='critical',
                reason="TBK DVR4104/DVR4216 Devices - Authentication Bypass detected",
                path='/device.rsp?opt=user&cmd=list',
            )
            return True
        return False

