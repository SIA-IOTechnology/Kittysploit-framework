#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""OSINT identity / subdomain harvesting for ``agent --all`` campaigns."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, MutableMapping, Optional, Sequence, Set

from interfaces.command_system.builtin.agent.agent_constants import (
    DERIVED_HOST_SCAN_MAX_HOSTS,
    EXPANDED_SURFACE_IDENTITY_MODULES,
    EXPANDED_SURFACE_INTEL_MAX_MODULES,
    EXPANDED_SURFACE_INTEL_MODULES,
    EXPANDED_SURFACE_PASSWORD_CANDIDATE_MAX,
    EXPANDED_SURFACE_SUBDOMAIN_MODULES,
    EXPANDED_SURFACE_USERNAME_CANDIDATE_MAX,
)

_EMAIL_RE = re.compile(
    r"\b([a-z0-9][a-z0-9._%+\-]{0,63}@[a-z0-9][a-z0-9.\-]{0,253}\.[a-z]{2,})\b",
    re.IGNORECASE,
)
_HANDLE_RE = re.compile(r"\b([a-z][a-z0-9._\-]{2,31})\b", re.IGNORECASE)

_DEFAULT_PASSWORDS = (
    "password",
    "Password1",
    "Password123",
    "admin",
    "admin123",
    "123456",
    "welcome",
    "changeme",
    "letmein",
    "qwerty",
    "summer",
    "winter",
    "spring",
    "autumn",
)


def organization_root_domain(hostname: str) -> str:
    host = (hostname or "").lower().strip(".")
    if host.startswith("www."):
        return host[4:]
    return host


def _dedupe_preserve(items: Iterable[str], *, limit: int) -> List[str]:
    seen: Set[str] = set()
    out: List[str] = []
    for raw in items:
        value = str(raw or "").strip()
        if not value:
            continue
        key = value.lower()
        if key in seen:
            continue
        seen.add(key)
        out.append(value)
        if len(out) >= limit:
            break
    return out


def _collect_strings(obj: Any, sink: List[str], depth: int = 0) -> None:
    if depth > 12 or len(sink) > 3000:
        return
    if isinstance(obj, dict):
        for value in obj.values():
            _collect_strings(value, sink, depth + 1)
    elif isinstance(obj, (list, tuple, set)):
        for value in list(obj)[:500]:
            _collect_strings(value, sink, depth + 1)
    elif isinstance(obj, (str, int, float, bool)):
        sink.append(str(obj))


def _hostname_in_org_family(root: str, candidate: str) -> bool:
    root = organization_root_domain(root)
    cand = organization_root_domain(candidate)
    if not root or not cand or "." not in cand:
        return False
    return cand == root or cand.endswith("." + root)


def harvest_subdomains_from_results(
    results: Sequence[Mapping[str, Any]],
    *,
    root_domain: str,
) -> List[str]:
    """Collect same-org hostnames from OSINT module outputs."""
    root = organization_root_domain(root_domain)
    found: List[str] = []
    for row in results or []:
        if not isinstance(row, dict):
            continue
        details = row.get("details") if isinstance(row.get("details"), dict) else {}
        for key in ("subdomains", "hosts", "discovered_hosts", "candidates"):
            value = details.get(key)
            if isinstance(value, (list, tuple, set)):
                for item in value:
                    host = str(item).strip().lower()
                    if host and _hostname_in_org_family(root, host):
                        found.append(host)
        strings: List[str] = []
        _collect_strings(details, strings)
        strings.append(str(row.get("message", "") or ""))
        blob = " ".join(strings)
        for token in re.findall(r"\b([a-z0-9][a-z0-9.\-]{2,200})\b", blob.lower()):
            if _hostname_in_org_family(root, token):
                found.append(token)
    return _dedupe_preserve(found, limit=DERIVED_HOST_SCAN_MAX_HOSTS * 2)


def harvest_identities_from_results(
    results: Sequence[Mapping[str, Any]],
    *,
    root_domain: str,
) -> Dict[str, List[str]]:
    """Extract emails, handles, and display names from OSINT rows."""
    root = organization_root_domain(root_domain)
    emails: List[str] = []
    handles: List[str] = []
    names: List[str] = []

    for row in results or []:
        if not isinstance(row, dict):
            continue
        details = row.get("details") if isinstance(row.get("details"), dict) else {}
        strings: List[str] = []
        _collect_strings(details, strings)
        strings.append(str(row.get("message", "") or ""))
        blob = " ".join(strings)

        for email in _EMAIL_RE.findall(blob):
            emails.append(email.lower())
            local = email.split("@", 1)[0]
            handles.append(local)

        for finding in details.get("findings", []) if isinstance(details.get("findings"), list) else []:
            if not isinstance(finding, dict):
                continue
            for key in ("email", "handle", "username", "name", "profile", "url"):
                val = finding.get(key)
                if not val:
                    continue
                text = str(val).strip()
                if "@" in text:
                    emails.append(text.lower())
                    handles.append(text.split("@", 1)[0])
                elif key == "name":
                    names.append(text)
                else:
                    handles.append(text)

        for handle in details.get("handles", []) if isinstance(details.get("handles"), list) else []:
            handles.append(str(handle))

    # Seed org mailbox patterns when we know the domain.
    if root and "." in root:
        for local in ("admin", "administrator", "info", "contact", "support", "hr", "sales", "webmaster"):
            emails.append(f"{local}@{root}")

    return {
        "emails": _dedupe_preserve(emails, limit=EXPANDED_SURFACE_USERNAME_CANDIDATE_MAX),
        "handles": _dedupe_preserve(handles, limit=EXPANDED_SURFACE_USERNAME_CANDIDATE_MAX),
        "names": _dedupe_preserve(names, limit=12),
    }


def build_username_candidates(identities: Mapping[str, Sequence[str]]) -> List[str]:
    candidates: List[str] = []
    for email in identities.get("emails", []) or []:
        candidates.append(str(email))
        local = str(email).split("@", 1)[0]
        candidates.append(local)
        for part in re.split(r"[._\-+]", local):
            if len(part) >= 2:
                candidates.append(part)
    for handle in identities.get("handles", []) or []:
        candidates.append(str(handle))
    for name in identities.get("names", []) or []:
        cleaned = re.sub(r"[^a-zA-Z ]", " ", str(name)).strip()
        parts = [p for p in cleaned.split() if p]
        if not parts:
            continue
        if len(parts) >= 2:
            first, last = parts[0], parts[-1]
            candidates.extend([
                first.lower(),
                last.lower(),
                f"{first.lower()}.{last.lower()}",
                f"{first[0].lower()}{last.lower()}",
                f"{first.lower()}{last.lower()}",
            ])
        else:
            candidates.append(parts[0].lower())
    candidates.extend(["admin", "administrator", "root", "user", "test"])
    return _dedupe_preserve(candidates, limit=EXPANDED_SURFACE_USERNAME_CANDIDATE_MAX)


def build_persona_password_candidates(
    identities: Mapping[str, Sequence[str]],
    *,
    root_domain: str = "",
) -> List[str]:
    """Guess likely weak passwords from identities (authorized assessments only)."""
    passwords: List[str] = list(_DEFAULT_PASSWORDS)
    root = organization_root_domain(root_domain)
    org_token = root.split(".", 1)[0] if root else ""

    for name in identities.get("names", []) or []:
        cleaned = re.sub(r"[^a-zA-Z ]", " ", str(name)).strip()
        parts = [p for p in cleaned.split() if len(p) >= 2]
        for part in parts:
            low = part.lower()
            cap = part[:1].upper() + part[1:].lower() if part else ""
            passwords.extend([low, cap, f"{low}123", f"{cap}123", f"{low}2024", f"{low}2025", f"{low}2026"])
        if len(parts) >= 2:
            first, last = parts[0], parts[-1]
            passwords.extend([
                f"{first.lower()}{last.lower()}",
                f"{last.lower()}{first.lower()}",
                f"{first.lower()}.{last.lower()}",
            ])

    for handle in identities.get("handles", []) or []:
        token = re.sub(r"[^a-z0-9]", "", str(handle).lower())
        if len(token) >= 3:
            passwords.extend([token, f"{token}123", f"{token}1"])

    if org_token and len(org_token) >= 3:
        passwords.extend([
            org_token,
            org_token.capitalize(),
            f"{org_token}123",
            f"{org_token}2024",
            f"{org_token}2025",
            f"{org_token}2026",
            f"Welcome{org_token.capitalize()}",
        ])

    return _dedupe_preserve(passwords, limit=EXPANDED_SURFACE_PASSWORD_CANDIDATE_MAX)


def merge_intel_into_knowledge_base(
    knowledge_base: MutableMapping[str, Any],
    *,
    identities: Mapping[str, Sequence[str]],
    subdomains: Sequence[str],
    username_candidates: Sequence[str],
    password_candidates: Sequence[str],
) -> None:
    if not isinstance(knowledge_base, dict):
        return
    existing_subs = list(knowledge_base.get("subdomain_candidates") or [])
    knowledge_base["subdomain_candidates"] = _dedupe_preserve(
        list(existing_subs) + list(subdomains),
        limit=DERIVED_HOST_SCAN_MAX_HOSTS * 2,
    )
    knowledge_base["identity_emails"] = list(identities.get("emails") or [])
    knowledge_base["identity_handles"] = list(identities.get("handles") or [])
    knowledge_base["identity_names"] = list(identities.get("names") or [])
    knowledge_base["username_candidates"] = _dedupe_preserve(
        list(knowledge_base.get("username_candidates") or []) + list(username_candidates),
        limit=EXPANDED_SURFACE_USERNAME_CANDIDATE_MAX,
    )
    knowledge_base["password_candidates"] = _dedupe_preserve(
        list(knowledge_base.get("password_candidates") or []) + list(password_candidates),
        limit=EXPANDED_SURFACE_PASSWORD_CANDIDATE_MAX,
    )
    if username_candidates or password_candidates:
        risk = set(knowledge_base.get("risk_signals") or [])
        risk.add("identity_enumerated")
        knowledge_base["risk_signals"] = sorted(risk)


def write_agent_wordlist(run_dir: Path, basename: str, lines: Sequence[str]) -> Optional[str]:
    if not lines:
        return None
    run_dir.mkdir(parents=True, exist_ok=True)
    path = run_dir / basename
    try:
        with open(path, "w", encoding="utf-8") as handle:
            for line in lines:
                value = str(line).strip()
                if value:
                    handle.write(value + "\n")
        return str(path)
    except OSError:
        return None


def pick_intel_modules(
    catalog_modules: Sequence[Mapping[str, Any]],
    *,
    max_modules: int = EXPANDED_SURFACE_INTEL_MAX_MODULES,
) -> List[Dict[str, Any]]:
    by_path = {
        str(row.get("path", "")).strip(): dict(row)
        for row in catalog_modules or []
        if str(row.get("path", "")).strip()
    }
    picked: List[Dict[str, Any]] = []
    for path in EXPANDED_SURFACE_INTEL_MODULES:
        row = by_path.get(path)
        if row:
            picked.append(row)
        if len(picked) >= max_modules:
            break
    return picked


def build_intel_option_overrides(
    module_path: str,
    *,
    root_domain: str,
    identities: Mapping[str, Sequence[str]],
) -> Dict[str, Any]:
    path = str(module_path or "").strip()
    root = organization_root_domain(root_domain)
    if path in EXPANDED_SURFACE_SUBDOMAIN_MODULES:
        return {"target": root}
    if path == "auxiliary/osint/email_infra_pivot":
        return {"target": root, "domain": root}
    if path == "auxiliary/osint/identity_handle_hunter":
        seed = ""
        for key in ("handles", "emails", "names"):
            values = identities.get(key) or []
            if values:
                seed = str(values[0])
                break
        if not seed and root:
            seed = f"admin@{root}"
        qtype = "email" if "@" in seed else "username"
        return {"query": seed, "query_type": qtype}
    if path == "auxiliary/osint/breach_exposure_score":
        seed = ""
        emails = identities.get("emails") or []
        if emails:
            seed = str(emails[0])
        elif root:
            seed = root
        target_type = "email" if "@" in seed else "domain"
        return {"target": seed, "target_type": target_type}
    if path == "auxiliary/osint/advanced_exposed_credentials_detector":
        return {"target": root}
    return {"target": root}
