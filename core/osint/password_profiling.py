#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""OSINT-driven persona password candidate generation (authorized assessments only)."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

_EMAIL_RE = re.compile(
    r"\b([a-z0-9][a-z0-9._%+\-]{0,63}@[a-z0-9][a-z0-9.\-]{0,253}\.[a-z]{2,})\b",
    re.IGNORECASE,
)

_DEFAULT_PASSWORDS: Tuple[str, ...] = (
    "Password1",
    "Password123",
    "Welcome1",
    "Changeme1",
    "Summer2026",
    "Winter2026",
)

_SEASONS = ("Spring", "Summer", "Autumn", "Winter", "Fall")
_SUFFIXES = ("!", "@", "#", "1", "12", "123", "1234")


@dataclass
class PersonaIntel:
    """Collected OSINT signals used to derive password candidates."""

    raw_target: str
    target_type: str = "unknown"
    first_name: str = ""
    last_name: str = ""
    full_name: str = ""
    handles: List[str] = field(default_factory=list)
    emails: List[str] = field(default_factory=list)
    domains: List[str] = field(default_factory=list)
    company_name: str = ""
    company_token: str = ""
    platforms: List[str] = field(default_factory=list)
    observed_local_parts: List[str] = field(default_factory=list)
    sources: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "raw_target": self.raw_target,
            "target_type": self.target_type,
            "first_name": self.first_name,
            "last_name": self.last_name,
            "full_name": self.full_name,
            "handles": self.handles,
            "emails": self.emails,
            "domains": self.domains,
            "company_name": self.company_name,
            "company_token": self.company_token,
            "platforms": self.platforms,
            "observed_local_parts": self.observed_local_parts,
            "sources": self.sources,
        }


def _dedupe_preserve(items: Iterable[str], *, limit: int) -> List[str]:
    seen = set()
    out: List[str] = []
    for raw in items:
        value = str(raw or "").strip()
        if not value or len(value) < 2:
            continue
        key = value.lower()
        if key in seen:
            continue
        seen.add(key)
        out.append(value)
        if len(out) >= limit:
            break
    return out


def organization_root_domain(hostname: str) -> str:
    host = (hostname or "").lower().strip(".")
    if host.startswith("www."):
        return host[4:]
    return host


def _apex_token(domain: str) -> str:
    root = organization_root_domain(domain)
    if not root or "." not in root:
        return ""
    return root.split(".", 1)[0]


def _title_word(word: str) -> str:
    w = str(word or "").strip()
    if not w:
        return ""
    return w[:1].upper() + w[1:].lower()


def _parse_person_name(text: str) -> Tuple[str, str, str]:
    cleaned = re.sub(r"[^a-zA-ZÀ-ÿ' \-]", " ", str(text or ""))
    parts = [p for p in cleaned.split() if len(p) >= 2]
    if not parts:
        return "", "", ""
    if len(parts) == 1:
        return parts[0].lower(), "", parts[0]
    first = parts[0]
    last = parts[-1]
    return first.lower(), last.lower(), f"{first} {last}".strip()


def _handles_from_email(email: str) -> List[str]:
    local = email.split("@", 1)[0]
    handles = [local]
    for part in re.split(r"[._\-+]", local):
        if len(part) >= 3:
            handles.append(part)
    return handles


def _detect_target_type(target: str, explicit: str = "") -> str:
    explicit = str(explicit or "").strip().lower()
    if explicit in ("person", "company", "email"):
        return explicit
    text = str(target or "").strip()
    if "@" in text:
        return "email"
    if "." in text and " " not in text and re.match(r"^[a-z0-9][a-z0-9.\-]*\.[a-z]{2,}$", text.lower()):
        return "company"
    return "person"


def parse_target(target: str, target_type: str = "auto") -> PersonaIntel:
    """Normalize a person name, email, or company domain into structured intel."""
    raw = str(target or "").strip()
    ttype = _detect_target_type(raw, target_type)
    intel = PersonaIntel(raw_target=raw, target_type=ttype, sources=["target_parse"])

    if ttype == "email":
        email = raw.lower()
        intel.emails.append(email)
        domain = email.split("@", 1)[1]
        intel.domains.append(domain)
        intel.company_token = _apex_token(domain)
        intel.handles.extend(_handles_from_email(email))
        local = email.split("@", 1)[0]
        if "." in local:
            parts = [p for p in local.split(".") if len(p) >= 2]
            if len(parts) >= 2:
                intel.first_name, intel.last_name = parts[0].lower(), parts[-1].lower()
                intel.full_name = f"{_title_word(parts[0])} {_title_word(parts[-1])}"
        elif len(local) >= 3:
            intel.handles.append(local)

    elif ttype == "company":
        domain = organization_root_domain(raw.lower())
        intel.domains.append(domain)
        intel.company_token = _apex_token(domain)
        intel.company_name = _title_word(intel.company_token)

    else:
        first, last, full = _parse_person_name(raw)
        intel.first_name = first
        intel.last_name = last
        intel.full_name = full
        if first:
            intel.handles.append(first)
        if last:
            intel.handles.append(last)
        if first and last:
            intel.handles.extend([
                f"{first}{last}",
                f"{first}.{last}",
                f"{first[0]}{last}",
                f"{first}_{last}",
            ])

    intel.handles = _dedupe_preserve(intel.handles, limit=20)
    intel.emails = _dedupe_preserve(intel.emails, limit=20)
    intel.domains = _dedupe_preserve(intel.domains, limit=10)
    return intel


def merge_intel_from_files(
    intel: PersonaIntel,
    *,
    identity_data: Optional[Mapping[str, Any]] = None,
    email_data: Optional[Mapping[str, Any]] = None,
    company_domain: str = "",
) -> PersonaIntel:
    """Enrich persona intel from optional OSINT module JSON outputs."""
    if company_domain:
        domain = organization_root_domain(company_domain)
        if domain and domain not in intel.domains:
            intel.domains.append(domain)
        if not intel.company_token:
            intel.company_token = _apex_token(domain)
        if not intel.company_name and intel.company_token:
            intel.company_name = _title_word(intel.company_token)
        intel.sources.append("company_domain_option")

    if isinstance(identity_data, dict) and identity_data:
        intel.sources.append("identity_handle_hunter")
        for finding in identity_data.get("findings", []) or []:
            if not isinstance(finding, dict):
                continue
            handle = str(finding.get("handle") or "").strip()
            platform = str(finding.get("platform") or "").strip()
            if handle:
                intel.handles.append(handle)
            if platform:
                intel.platforms.append(platform)
        for handle in identity_data.get("handles_tested", []) or []:
            intel.handles.append(str(handle))

        qtype = str(identity_data.get("query_type") or "")
        seed = str(identity_data.get("target") or "")
        if qtype == "name" and seed:
            first, last, full = _parse_person_name(seed)
            if first and not intel.first_name:
                intel.first_name = first
            if last and not intel.last_name:
                intel.last_name = last
            if full and not intel.full_name:
                intel.full_name = full
        elif qtype == "email" and "@" in seed:
            intel.emails.append(seed.lower())
            intel.handles.extend(_handles_from_email(seed.lower()))

    if isinstance(email_data, dict) and email_data:
        intel.sources.append("email_pattern_harvester")
        domain = str(email_data.get("target") or "")
        if domain:
            intel.domains.append(organization_root_domain(domain))
            if not intel.company_token:
                intel.company_token = _apex_token(domain)
        for email in email_data.get("emails", []) or []:
            intel.emails.append(str(email).lower())
        patterns = email_data.get("patterns") or {}
        for local in patterns.get("observed_local_parts", []) or []:
            intel.observed_local_parts.append(str(local))
            intel.handles.append(str(local))

    intel.handles = _dedupe_preserve(intel.handles, limit=30)
    intel.emails = _dedupe_preserve(intel.emails, limit=30)
    intel.domains = _dedupe_preserve(intel.domains, limit=10)
    intel.platforms = _dedupe_preserve(intel.platforms, limit=15)
    intel.observed_local_parts = _dedupe_preserve(intel.observed_local_parts, limit=20)
    intel.sources = _dedupe_preserve(intel.sources, limit=20)
    return intel


def apply_rdap_company_name(intel: PersonaIntel, rdap_payload: Mapping[str, Any]) -> PersonaIntel:
    """Extract organization label from RDAP JSON when available."""
    if not isinstance(rdap_payload, dict):
        return intel
    for entity in rdap_payload.get("entities", []) or []:
        if not isinstance(entity, dict):
            continue
        roles = [str(r).lower() for r in (entity.get("roles") or [])]
        if "registrant" not in roles and "administrative" not in roles:
            continue
        vcard = entity.get("vcardArray")
        if not isinstance(vcard, list) or len(vcard) < 2:
            continue
        for row in vcard[1]:
            if isinstance(row, list) and len(row) >= 4 and row[0] == "fn":
                name = str(row[3]).strip()
                if name and len(name) >= 2:
                    intel.company_name = name
                    intel.sources.append("rdap_org_name")
                    return intel
    return intel


def _add_scored(
    bucket: List[Tuple[str, int, str]],
    password: str,
    score: int,
    rationale: str,
) -> None:
    pwd = str(password or "").strip()
    if not pwd or len(pwd) < 4 or len(pwd) > 64:
        return
    bucket.append((pwd, score, rationale))


def _year_variants() -> List[str]:
    year = datetime.now(timezone.utc).year
    return [str(year), str(year - 1), str(year + 1)]


def build_scored_password_candidates(
    intel: PersonaIntel,
    *,
    count: int = 20,
) -> List[Dict[str, Any]]:
    count = max(1, min(50, int(count or 20)))
    scored: List[Tuple[str, int, str]] = []
    years = _year_variants()

    first = intel.first_name
    last = intel.last_name
    company = intel.company_token
    company_name = intel.company_name or _title_word(company)

    if first and last:
        combos = [
            (f"{first}{last}", 92, "first+last"),
            (f"{last}{first}", 88, "last+first"),
            (f"{first}.{last}", 90, "first.last"),
            (f"{_title_word(first)}{_title_word(last)}", 91, "FirstLast"),
            (f"{first[0]}{last}", 86, "initial+last"),
            (f"{first}{last[0]}", 82, "first+last initial"),
        ]
        for pwd, score, why in combos:
            _add_scored(scored, pwd, score, why)
            for year in years:
                _add_scored(scored, f"{pwd}{year}", score - 4, f"{why} + year")
            _add_scored(scored, f"{pwd}123", score - 6, f"{why} + 123")
            _add_scored(scored, f"{pwd}!", score - 8, f"{why} + !")

    for part in (first, last):
        if not part:
            continue
        cap = _title_word(part)
        _add_scored(scored, part, 78, "first or last name alone")
        _add_scored(scored, cap, 76, "capitalized name")
        for year in years:
            _add_scored(scored, f"{cap}{year}", 84, f"{cap} + current year")
            _add_scored(scored, f"{part}{year}", 80, f"{part} + year")
        _add_scored(scored, f"{part}123", 79, f"{part} + 123")
        _add_scored(scored, f"{cap}123!", 83, f"{cap}123!")

    if company and len(company) >= 3:
        cap_co = _title_word(company)
        _add_scored(scored, company, 74, "company token (domain apex)")
        _add_scored(scored, cap_co, 75, "capitalized company name")
        for year in years:
            _add_scored(scored, f"{company}{year}", 87, "company + year")
            _add_scored(scored, f"{cap_co}{year}", 88, "Company + year")
            _add_scored(scored, f"{cap_co}{year}!", 86, "Company + year + !")
        _add_scored(scored, f"{company}123", 85, "company + 123")
        _add_scored(scored, f"Welcome{cap_co}", 82, "Welcome + company")
        _add_scored(scored, f"{cap_co}@", 77, "company + @")
        for season in _SEASONS:
            _add_scored(scored, f"{season}{year}", 70, "season + year (common policy)")

    if company_name and company_name.lower() != (company or "").lower():
        _add_scored(scored, re.sub(r"[^a-zA-Z0-9]", "", company_name), 72, "legal company name (RDAP)")

    for handle in intel.handles[:8]:
        token = re.sub(r"[^a-z0-9]", "", handle.lower())
        if len(token) < 3:
            continue
        _add_scored(scored, token, 73, f"OSINT handle ({handle})")
        _add_scored(scored, f"{token}123", 81, "handle + 123")
        for year in years[:2]:
            _add_scored(scored, f"{token}{year}", 80, "handle + year")

    for local in intel.observed_local_parts[:6]:
        token = re.sub(r"[^a-z0-9]", "", local.lower())
        if len(token) >= 3:
            _add_scored(scored, f"{token}123", 77, "observed email pattern + 123")

    if first and company:
        _add_scored(scored, f"{first}{company}", 89, "first name + company")
        _add_scored(scored, f"{_title_word(first)}{_title_word(company)}", 90, "FirstName + Company")
        if last:
            _add_scored(scored, f"{first}{last}{company}", 87, "first+last+company")

    for platform in intel.platforms[:3]:
        plat = re.sub(r"[^a-z0-9]", "", platform.lower())
        if len(plat) >= 3 and first:
            _add_scored(scored, f"{first}{plat}", 68, f"first name + platform ({platform})")

    for default in _DEFAULT_PASSWORDS:
        _add_scored(scored, default, 45, "generic weak password")

    if company:
        _add_scored(scored, f"Password{company.capitalize()}", 71, "Password + company")

    # Deduplicate by password, keep highest score.
    best: Dict[str, Tuple[int, str]] = {}
    for pwd, score, rationale in scored:
        key = pwd.lower()
        if key not in best or score > best[key][0]:
            best[key] = (score, rationale)

    ranked = sorted(
        ({"password": pwd, "score": meta[0], "rationale": meta[1]} for pwd, meta in best.items()),
        key=lambda row: (-row["score"], row["password"]),
    )

    if len(ranked) < count:
        return ranked

    return ranked[:count]


def build_username_candidates_from_intel(intel: PersonaIntel, *, count: int = 24) -> List[str]:
    """Derive login identifiers from persona intel (emails, handles, names)."""
    candidates: List[str] = []
    for email in intel.emails:
        candidates.append(email)
        local = email.split("@", 1)[0]
        candidates.append(local)
        for part in re.split(r"[._\-+]", local):
            if len(part) >= 2:
                candidates.append(part)

    for handle in intel.handles:
        candidates.append(handle)

    if intel.first_name and intel.last_name:
        candidates.extend([
            intel.first_name,
            intel.last_name,
            f"{intel.first_name}.{intel.last_name}",
            f"{intel.first_name[0]}{intel.last_name}",
            f"{intel.first_name}{intel.last_name}",
        ])
    elif intel.first_name:
        candidates.append(intel.first_name)

    for local in intel.observed_local_parts:
        candidates.append(local)

    candidates.extend(["admin", "administrator", "root", "user", "test"])
    return _dedupe_preserve(candidates, limit=count)


def build_persona_password_list(
    identities: Mapping[str, Sequence[str]],
    *,
    root_domain: str = "",
    count: int = 32,
) -> List[str]:
    """Backward-compatible flat list for agent bruteforce wordlists."""
    intel = PersonaIntel(raw_target=root_domain or "org", target_type="company")
    if root_domain:
        domain = organization_root_domain(root_domain)
        intel.domains.append(domain)
        intel.company_token = _apex_token(domain)
        intel.company_name = _title_word(intel.company_token)

    for name in identities.get("names", []) or []:
        first, last, full = _parse_person_name(str(name))
        if first:
            intel.first_name = first
        if last:
            intel.last_name = last
        if full:
            intel.full_name = full

    intel.handles = _dedupe_preserve(identities.get("handles", []) or [], limit=30)
    intel.emails = _dedupe_preserve(identities.get("emails", []) or [], limit=30)

    return [row["password"] for row in build_scored_password_candidates(intel, count=count)]


def harvest_password_candidates_from_results(
    results: Sequence[Mapping[str, Any]],
    *,
    identities: Optional[Mapping[str, Sequence[str]]] = None,
    root_domain: str = "",
    count: int = 32,
) -> List[str]:
    extracted: List[str] = []
    for row in results or []:
        if not isinstance(row, dict):
            continue
        path = str(row.get("path", "") or "")
        details = row.get("details") if isinstance(row.get("details"), dict) else {}
        if "persona_password_profiler" not in path and "passwords" not in details:
            continue
        for item in details.get("passwords", []) or []:
            if isinstance(item, dict) and item.get("password"):
                extracted.append(str(item["password"]))
            elif isinstance(item, str) and item.strip():
                extracted.append(item.strip())

    generated = build_persona_password_list(
        identities or {},
        root_domain=root_domain,
        count=count,
    )
    return _dedupe_preserve(extracted + generated, limit=count)
