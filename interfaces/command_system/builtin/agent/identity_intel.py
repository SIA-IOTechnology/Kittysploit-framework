#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""OSINT identity / subdomain harvesting for ``agent --all`` campaigns."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Mapping, MutableMapping, Optional, Sequence, Set, Tuple

from core.osint.identity_handles import is_generic_handle
from core.osint.intel_synthesis import (
    distinct_org_emails,
    merge_osint_synthesis_into_knowledge_base,
    should_run_agent_intel_step,
    synthesize_intel_graph,
)
from core.osint.password_profiling import (
    build_persona_password_list,
    harvest_password_candidates_from_results,
    organization_root_domain,
)
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

# Agent ``--all`` phased OSINT (context-aware; skips redundant / low-value steps).
AGENT_INTEL_PIPELINE: Tuple[Tuple[str, str], ...] = (
    ("surface", "auxiliary/osint/domain_surface_mapper"),
    ("emails", "auxiliary/osint/email_pattern_harvester"),
    ("identity", "auxiliary/osint/identity_handle_hunter"),
    ("persona", "auxiliary/osint/persona_password_profiler"),
    ("breach", "auxiliary/osint/breach_exposure_score"),
    ("saas", "auxiliary/osint/saas_tenant_discovery"),
)

# Law-enforcement passive pipeline — no password profiling or credential generation.
AGENT_INTEL_PIPELINE_PASSIVE: Tuple[Tuple[str, str], ...] = (
    ("surface", "auxiliary/osint/domain_surface_mapper"),
    ("wayback", "auxiliary/osint/wayback_surface_hunter"),
    ("emails", "auxiliary/osint/email_pattern_harvester"),
    ("identity", "auxiliary/osint/identity_handle_hunter"),
    ("telegram", "auxiliary/osint/telegram_channel_profiler"),
    ("darkweb", "auxiliary/osint/darkweb_mention_hunter"),
    ("crypto", "auxiliary/osint/crypto_address_pivot"),
    ("breach", "auxiliary/osint/breach_exposure_score"),
    ("saas", "auxiliary/osint/saas_tenant_discovery"),
    ("github", "auxiliary/osint/github_org_exposure"),
)


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
        path = str(row.get("path", "") or "")
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

        if path.endswith("persona_password_profiler"):
            summary = details.get("intel_summary") if isinstance(details.get("intel_summary"), dict) else {}
            for key in ("full_name", "first_name", "last_name"):
                val = str(summary.get(key) or "").strip()
                if val and key == "full_name":
                    names.append(val)

    return {
        "emails": _dedupe_preserve(emails, limit=EXPANDED_SURFACE_USERNAME_CANDIDATE_MAX),
        "handles": _dedupe_preserve(handles, limit=EXPANDED_SURFACE_USERNAME_CANDIDATE_MAX),
        "names": _dedupe_preserve(names, limit=12),
    }


def build_username_candidates(identities: Mapping[str, Sequence[str]]) -> List[str]:
    candidates: List[str] = []
    for email in identities.get("emails", []) or []:
        email = str(email)
        candidates.append(email)
        local = email.split("@", 1)[0]
        if is_generic_handle(local):
            continue
        candidates.append(local)
        for part in re.split(r"[._\-+]", local):
            if len(part) >= 2 and not is_generic_handle(part):
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
    return build_persona_password_list(
        identities,
        root_domain=root_domain,
        count=EXPANDED_SURFACE_PASSWORD_CANDIDATE_MAX,
    )


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


def _distinct_org_emails(identities: Mapping[str, Sequence[str]], root: str) -> List[str]:
    return distinct_org_emails(identities, limit=EXPANDED_SURFACE_USERNAME_CANDIDATE_MAX)


def build_intel_option_overrides(
    module_path: str,
    *,
    root_domain: str,
    identities: Mapping[str, Sequence[str]],
    persona_seed: str = "",
) -> Dict[str, Any]:
    path = str(module_path or "").strip()
    root = organization_root_domain(root_domain)
    if path in EXPANDED_SURFACE_SUBDOMAIN_MODULES:
        return {"target": root}
    if path == "auxiliary/osint/email_infra_pivot":
        return {"target": root, "domain": root}
    if path == "auxiliary/osint/identity_handle_hunter":
        seed = str(persona_seed or "").strip()
        if not seed:
            for key in ("names", "handles"):
                values = identities.get(key) or []
                if values:
                    seed = str(values[0]).strip()
                    break
        if not seed:
            for email in _distinct_org_emails(identities, root):
                seed = email
                break
        if not seed:
            return {"query": "", "query_type": "name"}
        if "@" in seed:
            qtype = "email"
        elif " " in seed:
            qtype = "name"
        else:
            qtype = "username"
        return {"query": seed, "query_type": qtype}
    if path == "auxiliary/osint/breach_exposure_score":
        seed = ""
        emails = _distinct_org_emails(identities, root)
        if emails:
            seed = emails[0]
        elif root:
            seed = root
        target_type = "email" if "@" in seed else "domain"
        return {"target": seed, "target_type": target_type}
    if path == "auxiliary/osint/advanced_exposed_credentials_detector":
        return {"target": root}
    if path == "auxiliary/osint/email_pattern_harvester":
        return {"target": root, "scan_cert_names": True}
    if path == "auxiliary/osint/persona_password_profiler":
        seed = str(persona_seed or "").strip()
        names = identities.get("names") or []
        emails = _distinct_org_emails(identities, root)
        if not seed and names:
            seed = str(names[0])
        elif not seed and emails:
            seed = emails[0]
        if not seed:
            seed = root
        opts: Dict[str, Any] = {
            "target": seed,
            "company_domain": root,
            "password_count": "20",
        }
        if "@" in seed:
            opts["target_type"] = "email"
        elif seed == root:
            opts["target_type"] = "company"
        else:
            opts["target_type"] = "person"
        return opts
    if path == "auxiliary/osint/domain_surface_mapper":
        return {
            "target": root,
            "resolve_dns": True,
            "check_subdomains": True,
            "check_headers": True,
            "max_subdomains": "25",
        }
    if path == "auxiliary/osint/wayback_surface_hunter":
        return {"target": root, "max_urls": "400", "min_score": "50"}
    if path == "auxiliary/osint/github_org_exposure":
        return {"target": root, "max_repos": "20"}
    if path == "auxiliary/osint/telegram_channel_profiler":
        return {"target": root, "max_channels": "15"}
    if path == "auxiliary/osint/darkweb_mention_hunter":
        seed = root
        emails = _distinct_org_emails(identities, root)
        if emails:
            seed = emails[0]
        return {"target": seed}
    if path == "auxiliary/osint/crypto_address_pivot":
        return {
            "target": root,
            "enrich": True,
        }
    if path == "auxiliary/osint/saas_tenant_discovery":
        return {"target": root, "scan_cert_subdomains": True}
    return {"target": root}


def pick_agent_intel_pipeline_modules(
    catalog_modules: Sequence[Mapping[str, Any]],
    *,
    max_steps: int = EXPANDED_SURFACE_INTEL_MAX_MODULES,
    pipeline: Optional[Sequence[Tuple[str, str]]] = None,
) -> List[Dict[str, Any]]:
    steps = pipeline or AGENT_INTEL_PIPELINE
    by_path = {
        str(row.get("path", "")).strip(): dict(row)
        for row in catalog_modules or []
        if str(row.get("path", "")).strip()
    }
    picked: List[Dict[str, Any]] = []
    for _step, path in steps:
        row = by_path.get(path)
        if row:
            picked.append(row)
        if len(picked) >= max_steps:
            break
    return picked


def run_agent_intel_pipeline(
    *,
    execute_modules: Callable[[List[Dict[str, Any]], Dict[str, Dict[str, Any]]], Sequence[Mapping[str, Any]]],
    catalog_modules: Sequence[Mapping[str, Any]],
    root_domain: str,
    persona_seed: str = "",
    max_steps: int = EXPANDED_SURFACE_INTEL_MAX_MODULES,
    passive_only: bool = False,
    evidence_collector: Any = None,
    opsec_journal: Any = None,
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """
    Run OSINT modules in context-aware phases.

    Each step updates identities from prior results before the next module runs.
    When ``passive_only`` is set, credential profiling steps are excluded.
    """
    root = organization_root_domain(root_domain)
    step_pipeline = AGENT_INTEL_PIPELINE_PASSIVE if passive_only else AGENT_INTEL_PIPELINE
    pipeline = pick_agent_intel_pipeline_modules(
        catalog_modules,
        max_steps=max_steps,
        pipeline=step_pipeline,
    )
    all_results: List[Dict[str, Any]] = []
    running_identities: Dict[str, List[str]] = {"emails": [], "handles": [], "names": []}
    if persona_seed:
        running_identities["names"].append(str(persona_seed).strip())

    for step, path in step_pipeline:
        module = next((row for row in pipeline if str(row.get("path", "")) == path), None)
        if not module:
            continue
        if not should_run_agent_intel_step(
            step,
            persona_seed=persona_seed,
            identities=running_identities,
            root_domain=root,
        ):
            continue

        if opsec_journal is not None:
            violation = opsec_journal.check_passive_violation(path)
            if violation:
                continue

        overrides = {
            path: build_intel_option_overrides(
                path,
                root_domain=root,
                identities=running_identities,
                persona_seed=persona_seed,
            )
        }
        batch = execute_modules([module], overrides)
        for row in list(batch or []):
            if not isinstance(row, dict):
                continue
            row = dict(row)
            row.setdefault("target", root)
            if evidence_collector is not None:
                try:
                    row = evidence_collector.record_module_result(row)
                except Exception:
                    from core.osint.evidence import envelope_module_result_row

                    row = envelope_module_result_row(row)
            else:
                from core.osint.evidence import envelope_module_result_row

                row = envelope_module_result_row(row)
            all_results.append(row)
            if opsec_journal is not None:
                try:
                    opsec_journal.record(
                        action="module_complete",
                        module=path,
                        target=root,
                        status=str(row.get("status") or "ok"),
                    )
                except Exception:
                    pass

        harvested = harvest_identities_from_results(all_results, root_domain=root)
        for key in ("emails", "handles", "names"):
            running_identities[key] = _dedupe_preserve(
                list(running_identities.get(key) or []) + list(harvested.get(key) or []),
                limit=EXPANDED_SURFACE_USERNAME_CANDIDATE_MAX if key != "names" else 12,
            )

    synthesis = synthesize_intel_graph(
        all_results,
        root_domain=root,
        identities=running_identities,
        persona_seed=persona_seed,
    )
    if evidence_collector is not None:
        try:
            evidence_collector.record_synthesis(synthesis)
        except Exception:
            pass
    return all_results, synthesis
