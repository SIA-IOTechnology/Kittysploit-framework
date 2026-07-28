#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""When using Apache Tomcat versions 10."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Apache Tomcat Remote Command Execution Detection',
        'description': 'When using Apache Tomcat versions 10.0.0-M1 to 10.0.0-M4, 9.0.0.M1 to 9.0.34, 8.5.0 to 8.5.54 and 7.0.0 to 7.0.103 if a) an attacker is able to control the contents and name of a file on the server; and b) the server is configured to use the PersistenceManager with a FileStore; and c) the PersistenceManager is configured with sessionAttributeValueClassNameFilter="null" (the default unless a SecurityManager is used) or a sufficiently lax filter to allow the attacker provided object to be deserialized; and d) the attacker knows the relative file path from the storage location used by FileStore to the file the attacker has control over; then, using a specifically crafted request, the attacker will be able to trigger remote code execution via deserialization of the file under their control. Note that all of conditions a) to d) must be true for the attack to succeed.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2020', 'rce', 'packetstorm', 'apache', 'tomcat', 'vuln'],
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
            'http://packetstormsecurity.com/files/157924/Apache-Tomcat-CVE-2020-9484-Proof-Of-Concept.html',
            'https://nvd.nist.gov/vuln/detail/CVE-2020-9484',
            'https://lists.apache.org/thread.html/r77eae567ed829da9012cadb29af17f2df8fa23bf66faf88229857bb1%40%3Cannounce.tomcat.apache.org%3E',
            'https://lists.apache.org/thread.html/rf70f53af27e04869bdac18b1fc14a3ee529e59eb12292c8791a77926@%3Cusers.tomcat.apache.org%3E',
            'http://lists.opensuse.org/opensuse-security-announce/2020-05/msg00057.html',
        ],
        'cve': 'CVE-2020-9484',
    }

    def run(self):
        r = self.http_request(method="GET", path='/index.jsp', allow_redirects=False)
        if not r or r.status_code != 500:
            return False
        body = r.text or ""
        body_all = ('Exception', 'ObjectInputStream', 'PersistentManagerBase',)
        if (all(m in body for m in body_all)):
            self.set_info(
                severity='high',
                reason="Apache Tomcat Remote Command Execution detected",
                path='/index.jsp',
            )
            return True
        return False

