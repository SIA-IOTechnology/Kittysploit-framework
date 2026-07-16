#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect exposed Kubernetes Dashboard UI."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        "name": "Kubernetes Dashboard Detection",
        "description": "Detects Kubernetes Dashboard login UI and proxy API paths.",
        "author": ["KittySploit Team"],
        "severity": "medium",
        "tags": ["web", "scanner", "kubernetes", "k8s", "dashboard", "panel"],
    'agent': {
        'risk': 'active',
        'effects': ['network_probe'],
        'expected_requests': 4,
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
                                   {'capability': 'db_access', 'from_detail': ''}],
         'consumes_capabilities': [],
         'option_bindings': {},
         'suggested_followups': []},
    },
    }

    def run(self):
        for path in (
            "/api/v1/namespaces/kubernetes-dashboard/services/https:kubernetes-dashboard:/proxy/",
            "/#/login",
            "/api/v1/namespaces/kube-system/services/https:kubernetes-dashboard:/proxy/",
        ):
            r = self.http_request(method="GET", path=path, allow_redirects=True)
            if not r:
                continue
            body = (r.text or "").lower()
            if "kubernetes dashboard" in body or "kubernetes-dashboard" in body or "k8s" in body and "dashboard" in body:
                self.set_info(severity="medium", reason="Kubernetes Dashboard detected", path=path)
                return True
        return False
