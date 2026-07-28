#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Apache Hadoop YARN ResourceManager is susceptible to remote code execution."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Apache Hadoop YARN ResourceManager - Remote Code Execution Detection',
        'description': 'Apache Hadoop YARN ResourceManager is susceptible to remote code execution. An attacker can execute malware, obtain sensitive information, modify data, and/or gain full control over a compromised system without entering necessary credentials.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'misconfiguration', 'vulhub', 'apache', 'hadoop', 'unauth', 'rce', 'msf', 'misconfig', 'vuln'],
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
                'suggested_followups': [],
            },
        },
        'references': [
            'http://archive.hack.lu/2016/Wavestone%20-%20Hack.lu%202016%20-%20Hadoop%20safari%20-%20Hunting%20for%20vulnerabilities%20-%20v1.0.pdf',
            'https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/linux/http/hadoop_unauth_exec.rb',
            'https://github.com/vulhub/vulhub/tree/master/hadoop/unauthorized-yarn',
            'https://github.com/Al1ex/Hadoop-Yarn-ResourceManager-RCE',
        ],
    }

    def run(self):
        path = '/ws/v1/cluster/apps/new-application'
        r = self.http_request(method='POST', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('"application-id"',)
        if any(m in body for m in body_any):
            self.set_info(
                severity='critical',
                reason='Apache Hadoop YARN ResourceManager - Remote Code Execution detected',
                path=path,
            )
            return True
        return False

