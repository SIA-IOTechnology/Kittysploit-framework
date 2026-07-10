#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Détection Elasticsearch (API REST exposée)."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):

    __info__ = {
        "name": "Elasticsearch detection",
        "description": "Detects exposed Elasticsearch REST API (often unauthenticated).",
        "author": "KittySploit Team",
        "severity": "medium",
        "modules": [],
        "tags": ["web", "scanner", "elasticsearch", "elastic", "database", "disclosure"],
    'agent': {
        'risk': 'active',
        'effects': ['network_probe'],
        'expected_requests': 2,
        'reversible': True,
        'approval_required': False,
        'produces': ['tech_hints', 'risk_signals', 'endpoints'],
        'cost': 1.0,
        'noise': 0.5,
        'value': 1.0,
        'requires':         {'min_endpoints': 0,
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
         'api_surface_ready': False},
        'chain':         {'produces_capabilities': [{'capability': 'ssrf_primitive', 'from_detail': ''},
                                   {'capability': 'file_read', 'from_detail': 'lfi_path'},
                                   {'capability': 'lfi_param', 'from_detail': 'lfi_param'}],
         'consumes_capabilities': [],
         'option_bindings': {},
         'suggested_followups': []},
    },
    }

    @staticmethod
    def _is_elasticsearch_response(body: str) -> bool:
        """
        Avoid false positives: many JSON/HTML pages contain both 'version' and 'number'.
        Require Elasticsearch-specific markers (official root tagline, cluster health fields, etc.).
        """
        if not body:
            return False
        t = body.lower()
        # Almost unique to ES GET /
        if "you know, for search" in t:
            return True
        # Build / Lucene fields from ES version block (together, not loose 'version'+'number')
        if "lucene_version" in t and ("build_hash" in t or "build_flavor" in t):
            return True
        if "cluster_name" in t:
            if "elasticsearch" in t:
                return True
            # /_cluster/health-style payload
            if any(
                x in t
                for x in (
                    "active_shards",
                    "relocating_shards",
                    "initializing_shards",
                    "unassigned_shards",
                    "delayed_unassigned_shards",
                    "number_of_nodes",
                    "number_of_data_nodes",
                )
            ):
                return True
            if "timed_out" in t and "number_of_pending_tasks" in t:
                return True
        return False

    def run(self):
        for path in ["/", "/_cluster/health", "/_nodes"]:
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            if self._is_elasticsearch_response(r.text):
                self.set_info(severity="medium", reason="Elasticsearch API exposed")
                return True
        return False
