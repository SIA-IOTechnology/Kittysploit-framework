#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Détection Google Cloud Storage exposé."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):

    __info__ = {
        "name": "GCP Storage detection",
        "description": "Detects Google Cloud Storage API (XML/JSON listing or GCP error format).",
        "author": "KittySploit Team",
        "severity": "medium",
        "modules": [],
        "tags": ["cloud", "scanner", "gcp", "google", "storage", "bucket"],
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
        'chain':         {'produces_capabilities': [{'capability': 'ssrf_primitive', 'from_detail': ''}],
         'consumes_capabilities': [],
         'option_bindings': {},
         'suggested_followups': []},
    },
    }

    def run(self):
        r = self.http_request(method="GET", path="/", allow_redirects=False)
        if not r:
            return False
        t = r.text
        # GCS XML API: ListBucketResult with namespace or gs-specific
        if "ListBucketResult" in t and ("google" in t.lower() or "storage" in t.lower() or "gs" in t):
            self.set_info(severity="medium", reason="GCP Storage (ListBucketResult)")
            return True
        if "NoSuchKey" in t or "AccessDenied" in t:
            h = {k.lower(): v for k, v in r.headers.items()}
            if "x-guploader" in str(h.keys()).lower() or "goog" in str(h.values()).lower():
                self.set_info(severity="medium", reason="GCP Storage (headers/error)")
                return True
        h = {k.lower(): v for k, v in r.headers.items()}
        if h.get("x-guploader-uploadid") or h.get("x-goog-generation"):
            self.set_info(severity="medium", reason="GCP Storage (x-goog-* / x-guploader-*)")
            return True
        return False
