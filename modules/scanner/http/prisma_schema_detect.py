#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Prisma is a modern ORM extremely popular in the Node."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Exposed Prisma Database Schema - Exposure Detection',
        'description': 'Prisma is a modern ORM extremely popular in the Node.js and TypeScript (Next.js/Express) ecosystems. Developers often accidentally expose the `prisma/` folder in web directories during deployments or Docker builds. This template checks for the exposure of the `schema.prisma` file, which typically contains the complete internal database table definitions, architectures, and the database connection strings (URLs) pointing to AWS RDS, PostgreSQL, or SQLite databases.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'exposure', 'prisma', 'database', 'config', 'custom'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 5,
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
    }

    def run(self):
        for path in ('/schema.prisma', '/prisma/schema.prisma', '/src/prisma/schema.prisma', '/db/schema.prisma', '/.prisma/schema.prisma'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            body_all = ('generator', 'datasource', 'provider =', 'model',)
            if (all(m in body for m in body_all)):
                self.set_info(
                    severity='medium',
                    reason="Exposed Prisma Database Schema - Exposure detected",
                    path=path,
                )
                return True
        return False

