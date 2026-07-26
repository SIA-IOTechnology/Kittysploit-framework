#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Industry MoU request templates for lawful provider cooperation (e-evidence)."""

from __future__ import annotations

from typing import Any, Dict, List, Mapping, Optional, Sequence

from core.osint.evidence import utc_now_z


# Platforms commonly covered by national/EU MoU frameworks with LE.
MOU_PLATFORM_CATALOG: Dict[str, Dict[str, Any]] = {
    "microsoft": {
        "label": "Microsoft",
        "portal": "https://learn.microsoft.com/en-us/legal/ediscovery/",
        "categories": ["identity", "mailbox", "teams", "azure_signin_logs"],
    },
    "google": {
        "label": "Google",
        "portal": "https://support.google.com/a/answer/7676355",
        "categories": ["account", "gmail", "drive", "login_ip"],
    },
    "meta": {
        "label": "Meta",
        "portal": "https://www.facebook.com/records/login/",
        "categories": ["account", "messages", "login_ip", "device"],
    },
    "apple": {
        "label": "Apple",
        "portal": "https://www.apple.com/legal/transparency/",
        "categories": ["account", "icloud", "device", "login_ip"],
    },
    "cloudflare": {
        "label": "Cloudflare",
        "portal": "https://www.cloudflare.com/trust-hub/abuse-approach/",
        "categories": ["dns_logs", "ip_logs", "account"],
    },
}


def build_industry_mou_request(
    *,
    platform: str,
    case_id: str,
    legal_basis: str,
    data_categories: Optional[Sequence[str]] = None,
    identifiers: Optional[Mapping[str, Any]] = None,
    contact_reference: str = "",
) -> Dict[str, Any]:
    key = str(platform or "").strip().lower()
    catalog = MOU_PLATFORM_CATALOG.get(key, {})
    label = str(catalog.get("label") or platform or "Unknown Provider")
    categories = list(data_categories or catalog.get("categories") or ["account", "login_ip"])
    return {
        "format": "industry_mou_request_template",
        "version": "1",
        "createdAt": utc_now_z(),
        "platform": label,
        "platformKey": key or platform,
        "providerPortal": catalog.get("portal"),
        "caseReference": case_id,
        "legalBasis": legal_basis,
        "dataCategoriesRequested": categories,
        "subjectIdentifiers": dict(identifiers or {}),
        "nationalContactReference": contact_reference,
        "handling": {
            "tlp": "AMBER",
            "notes": "Submit via official LE portal / MoU channel with judicial authorization attached.",
        },
    }


def build_mou_requests_from_osint(
    synthesis: Mapping[str, Any],
    module_results: Optional[Sequence[Mapping[str, Any]]] = None,
    *,
    case_id: str = "",
    legal_basis: str = "",
) -> List[Dict[str, Any]]:
    """Suggest industry MoU templates from SaaS / identity OSINT hits."""
    requests: List[Dict[str, Any]] = []
    root = str(synthesis.get("root_domain") or "")

    saas_providers: List[str] = []
    for node in synthesis.get("nodes") or []:
        if isinstance(node, Mapping) and node.get("type") == "saas":
            saas_providers.append(str(node.get("label") or ""))

    platform_map = {
        "microsoft": "microsoft",
        "o365": "microsoft",
        "office": "microsoft",
        "azure": "microsoft",
        "google": "google",
        "gsuite": "google",
        "workspace": "google",
        "okta": "okta",
        "facebook": "meta",
        "instagram": "meta",
        "whatsapp": "meta",
    }

    for provider in saas_providers:
        low = provider.lower()
        matched = ""
        for token, key in platform_map.items():
            if token in low:
                matched = key
                break
        if matched in MOU_PLATFORM_CATALOG:
            requests.append(
                build_industry_mou_request(
                    platform=matched,
                    case_id=case_id,
                    legal_basis=legal_basis,
                    identifiers={"domain": root, "tenant_hint": provider},
                )
            )

    emails: List[str] = []
    for node in synthesis.get("nodes") or []:
        if isinstance(node, Mapping) and node.get("type") == "email":
            emails.append(str(node.get("label") or ""))

    if emails and not requests:
        domain = emails[0].split("@")[-1] if emails else root
        guess = "google" if "gmail" in domain else "microsoft"
        requests.append(
            build_industry_mou_request(
                platform=guess,
                case_id=case_id,
                legal_basis=legal_basis,
                identifiers={"email": emails[0], "domain": root},
            )
        )

    return requests[:8]
