#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""AnythingLLM is an application that turns pieces of content into context that any LLM can use as references dur."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'AnythingLLM - Information Disclosure Detection',
        'description': 'AnythingLLM is an application that turns pieces of content into context that any LLM can use as references during chatting. If AnythingLLM prior to version 1.10.0 is configured to use Qdrant as the vector database with an API key, this QdrantApiKey could be exposed in plain text to unauthenticated users via the `/api/setup-complete` endpoint. Leakage of QdrantApiKey allows an unauthenticated attacker full read/write access to the Qdrant vector database instance used by AnythingLLM. Since Qdrant often stores the core knowledge base for RAG in AnythingLLM, this can lead to complete compromise of the semantic search / retrieval functionality and indirect leakage of confidential uploaded documents. Version 1.10.0 patches the issue.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2026', 'anything-llm', 'info-leak', 'api', 'vkev'],
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
        'references': [
            'https://github.com/Mintplex-Labs/anything-llm/security/advisories/GHSA-gm94-qc2p-xcwf',
            'https://nvd.nist.gov/vuln/detail/CVE-2026-24477',
        ],
        'cve': 'CVE-2026-24477',
    }

    def run(self):
        path = '/api/setup-complete'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        content_type = r.headers.get("Content-Type") or r.headers.get("content-type") or ""
        body_any = ('"QdrantApiKey":',)
        ctype_any = ('application/json',)
        if (any(m in body for m in body_any)) and (any(m in content_type for m in ctype_any)):
            self.set_info(
                severity='high',
                reason='AnythingLLM - Information Disclosure detected',
                path=path,
            )
            return True
        return False

