#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""All in One SEO Pack for WordPress contains a full path disclosure vulnerability due to improper access restric."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'WordPress All in One SEO Pack - Full Path Disclosure Detection',
        'description': 'All in One SEO Pack for WordPress contains a full path disclosure vulnerability due to improper access restrictions in its source files, allowing unauthenticated attackers to retrieve full server paths and aiding exploitation.',
        'author': ['KittySploit Team'],
        'severity': 'low',
        'tags': ['web', 'scanner', 'misconfiguration', 'debug', 'wordpress', 'wp', 'wp-plugin', 'all-in-one-seo-pack', 'fpd'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 5,
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
        'references': ['https://wordpress.org/plugins/all-in-one-seo-pack/'],
    }

    def run(self):
        for path in ('/wp-content/plugins/all-in-one-seo-pack/vendor/woocommerce/action-scheduler/classes/ActionScheduler_AdminView.php', '/wp-content/plugins/all-in-one-seo-pack/vendor/woocommerce/action-scheduler/classes/ActionScheduler_ListTable.php', '/wp-content/plugins/all-in-one-seo-pack/vendor/woocommerce/action-scheduler/classes/abstracts/ActionScheduler_Abstract_QueueRunner.php', '/wp-content/plugins/all-in-one-seo-pack/vendor/woocommerce/action-scheduler/classes/abstracts/ActionScheduler_Store.php', '/wp-content/plugins/all-in-one-seo-pack/vendor/woocommerce/action-scheduler/classes/abstracts/ActionScheduler_Abstract_ListTable.php'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            body_any = ('all-in-one-seo-pack',)
            body_all = ('Fatal error', 'Uncaught Error', 'Warning:', 'failed to open stream',)
            if (any(m in body for m in body_any)) and (all(m in body for m in body_all)):
                self.set_info(
                    severity='low',
                    reason="WordPress All in One SEO Pack - Full Path Disclosure detected",
                    path=path,
                )
                return True
        return False

