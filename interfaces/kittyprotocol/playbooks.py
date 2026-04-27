#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Finding type -> ordered checklist + KittySploit module hints (mapping observation -> action).
"""

from typing import Any, Dict, List

PLAYBOOKS: Dict[str, Dict[str, Any]] = {
    "cleartext_credentials_or_tokens": {
        "title": "Cleartext secrets",
        "checklist": [
            "Confirm expected transport security (TLS expected or not).",
            "Identify token scope (session, API, SSO).",
            "Test reuse on other hosts/paths.",
        ],
        "modules_in_order": [
            {"module": "auxiliary/scanner/http/http_login", "reason": "Test HTTP credential reuse"},
            {"module": "auxiliary/scanner/ssl/ssl_version", "reason": "Check service-side TLS configuration"},
        ],
    },
    "missing_authentication_pattern": {
        "title": "No visible authentication",
        "checklist": [
            "Replay the request without auth headers.",
            "Compare response bodies with/without session.",
            "Map nearby endpoints on the same host.",
        ],
        "modules_in_order": [
            {"module": "auxiliary/scanner/http/http_enum", "reason": "Enumerate HTTP surface"},
            {"module": "auxiliary/scanner/http/crawler", "reason": "Discover related paths"},
        ],
    },
    "replayable_requests": {
        "title": "Replayable requests",
        "checklist": [
            "Verify idempotence and server-side side effects.",
            "Test reordering and duplicate send.",
            "Look for anti-replay tokens or nonces.",
        ],
        "modules_in_order": [
            {"module": "auxiliary/scanner/http/http_repeater_proxy", "reason": "Proxy and replay requests (if available in your branch)"},
            {"module": "auxiliary/scanner/http/api_fuzzer", "reason": "Fuzz on the same API surface"},
        ],
    },
    "suspicious_field_lengths_or_anomalies": {
        "title": "Length/parsing anomalies",
        "checklist": [
            "Isolate the anomalous field and boundary values.",
            "Monitor server errors and response times.",
            "Test encodings and boundaries (chunk, UTF-8, null).",
        ],
        "modules_in_order": [
            {"module": "auxiliary/fuzzers/http/http_form_field", "reason": "Targeted field fuzzing (if module exists)"},
            {"module": "auxiliary/scanner/http/api_fuzzer", "reason": "Generic API fuzzing"},
        ],
    },
    "sensitive_commands_or_endpoints": {
        "title": "Sensitive surface",
        "checklist": [
            "Identify required roles for each HTTP verb.",
            "Test escalation and admin/debug paths.",
            "Correlate with application logs if accessible.",
        ],
        "modules_in_order": [
            {"module": "auxiliary/scanner/http/crawler", "reason": "Map sensitive links"},
            {"module": "auxiliary/scanner/http/dir_scanner", "reason": "Directory discovery"},
        ],
    },
}

OBSERVATION_MODULE_MAP: Dict[str, List[str]] = {
    "cleartext_credentials_or_tokens": [
        "auxiliary/scanner/http/http_login",
        "auxiliary/scanner/ssl/ssl_version",
        "auxiliary/scanner/telnet/telnet_version",
    ],
    "missing_authentication_pattern": [
        "auxiliary/scanner/http/http_enum",
        "auxiliary/scanner/http/crawler",
    ],
    "replayable_requests": [
        "auxiliary/scanner/http/api_fuzzer",
    ],
    "sensitive_commands_or_endpoints": [
        "auxiliary/scanner/http/crawler",
        "auxiliary/scanner/http/dir_scanner",
    ],
}


def get_playbook(pattern_type: str) -> Dict[str, Any]:
    return dict(PLAYBOOKS.get(pattern_type, {
        "title": pattern_type,
        "checklist": ["Document the observation.", "Prioritize manual tests or generic modules."],
        "modules_in_order": [],
    }))


def modules_for_observation(pattern_type: str) -> List[str]:
    return list(OBSERVATION_MODULE_MAP.get(pattern_type, []))
