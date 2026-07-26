#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
SIRIUS platform connector (EU Commission — electronic evidence from service providers).

Generates structured preservation / disclosure request templates aligned with
SIRIUS categories. Live API push requires institutional credentials.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any, Dict, List, Mapping, Optional, Sequence

from core.osint.config import get_osint_config
from core.osint.evidence import utc_now_z


# Common SIRIUS / e-evidence data categories (illustrative taxonomy).
SIRIUS_DATA_CATEGORIES = (
    "basic_user_information",
    "access_logs",
    "content_data",
    "transactional_data",
    "ip_addresses",
    "device_identifiers",
    "account_metadata",
)


def build_sirius_request_template(
    *,
    case_id: str,
    legal_basis: str,
    provider: str,
    data_categories: Optional[Sequence[str]] = None,
    subject_identifiers: Optional[Mapping[str, Any]] = None,
    urgency: str = "standard",
    preservation: bool = True,
) -> Dict[str, Any]:
    categories = [str(c) for c in (data_categories or SIRIUS_DATA_CATEGORIES[:4]) if c]
    identifiers = dict(subject_identifiers or {})
    return {
        "format": "sirius_request_template",
        "version": "1",
        "createdAt": utc_now_z(),
        "caseReference": case_id,
        "legalBasis": legal_basis,
        "serviceProvider": provider,
        "requestType": "preservation_and_disclosure" if preservation else "disclosure",
        "urgency": urgency,
        "dataCategories": categories,
        "subjectIdentifiers": identifiers,
        "notes": (
            "Template for national SIRIUS contact point / mutual legal assistance workflow. "
            "Submit via official SIRIUS portal with validated judicial authorization."
        ),
    }


def build_sirius_requests_from_osint(
    synthesis: Mapping[str, Any],
    module_results: Optional[Sequence[Mapping[str, Any]]] = None,
    *,
    case_id: str = "",
    legal_basis: str = "",
) -> List[Dict[str, Any]]:
    """Suggest provider-specific SIRIUS templates from OSINT findings."""
    requests: List[Dict[str, Any]] = []
    providers_seen: set = set()

    for node in synthesis.get("nodes") or []:
        if not isinstance(node, Mapping):
            continue
        if str(node.get("type") or "") != "saas":
            continue
        provider = str(node.get("label") or "")
        if not provider or provider in providers_seen:
            continue
        providers_seen.add(provider)
        requests.append(
            build_sirius_request_template(
                case_id=case_id,
                legal_basis=legal_basis,
                provider=provider,
                data_categories=["basic_user_information", "access_logs", "ip_addresses"],
                subject_identifiers={"organization_domain": synthesis.get("root_domain")},
            )
        )

    for row in module_results or []:
        if not isinstance(row, Mapping):
            continue
        path = str(row.get("path") or "")
        details = row.get("details") if isinstance(row.get("details"), dict) else {}
        if "telegram" in path:
            for finding in details.get("findings") or []:
                if not isinstance(finding, dict):
                    continue
                username = str(finding.get("username") or "")
                if username:
                    requests.append(
                        build_sirius_request_template(
                            case_id=case_id,
                            legal_basis=legal_basis,
                            provider="Telegram",
                            data_categories=["basic_user_information", "access_logs", "content_data"],
                            subject_identifiers={"username": username},
                        )
                    )

    if not requests and synthesis.get("root_domain"):
        requests.append(
            build_sirius_request_template(
                case_id=case_id,
                legal_basis=legal_basis,
                provider="Generic Cloud / IdP",
                data_categories=list(SIRIUS_DATA_CATEGORIES[:5]),
                subject_identifiers={"domain": synthesis.get("root_domain")},
            )
        )
    return requests[:12]


def push_sirius_template(
    template: Mapping[str, Any],
    *,
    url: str,
    token: str,
    timeout: int = 30,
) -> Dict[str, Any]:
    """POST template to institutional SIRIUS API gateway (when configured)."""
    base = str(url or "").strip().rstrip("/")
    auth = str(token or "").strip()
    if not base or not auth:
        return {"ok": False, "error": "SIRIUS URL and token required"}

    payload = json.dumps(dict(template)).encode("utf-8")
    req = urllib.request.Request(
        f"{base}/api/v1/requests",
        data=payload,
        method="POST",
        headers={
            "Authorization": f"Bearer {auth}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8", errors="replace")
            return {"ok": True, "status": resp.status, "body": body[:1500]}
    except urllib.error.HTTPError as exc:
        return {"ok": False, "status": exc.code, "error": exc.read().decode("utf-8", errors="replace")[:500]}
    except OSError as exc:
        return {"ok": False, "error": str(exc)}
