#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""OSINT evidence envelope, chain-of-custody, and ledger integration."""

from __future__ import annotations

import hashlib
import importlib.util
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Mapping, MutableMapping, Optional, Sequence, Type

from core.schemas import SCHEMA_VERSION

_OSINT_MODULE_PREFIX = "auxiliary/osint/"

_LEDGER_PATH = (
    Path(__file__).resolve().parents[2]
    / "interfaces"
    / "command_system"
    / "builtin"
    / "agent"
    / "evidence_ledger.py"
)


def _load_evidence_ledger_class() -> Type[Any]:
    spec = importlib.util.spec_from_file_location("kitty_agent_evidence_ledger", _LEDGER_PATH)
    if spec is None or spec.loader is None:
        raise ImportError(f"Unable to load evidence ledger from {_LEDGER_PATH}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.EvidenceLedger

# Per-module baseline confidence (passive, API-verified sources score higher).
_MODULE_CONFIDENCE: Dict[str, float] = {
    "domain_surface_mapper": 0.82,
    "domain_dns": 0.85,
    "domain_crtsh": 0.88,
    "domain_whois": 0.80,
    "passive_dns_aggregator": 0.86,
    "reverse_whois_org_mapper": 0.72,
    "identity_handle_hunter": 0.78,
    "email_pattern_harvester": 0.75,
    "breach_exposure_score": 0.65,
    "github_org_exposure": 0.80,
    "wayback_surface_hunter": 0.72,
    "cdn_origin_ip_finder": 0.70,
    "saas_tenant_discovery": 0.76,
    "identity_exposure_graph": 0.74,
    "telegram_channel_profiler": 0.74,
    "darkweb_mention_hunter": 0.68,
    "crypto_address_pivot": 0.76,
    "subdomain_takeover_hint": 0.77,
}


def utc_now_z() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def content_sha256(value: Any) -> str:
    if isinstance(value, (dict, list)):
        payload = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
    else:
        payload = str(value)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _module_slug(module_path: str) -> str:
    path = str(module_path or "").strip().lower()
    if not path:
        return ""
    return path.rsplit("/", 1)[-1]


def infer_osint_confidence(module_path: str, details: Mapping[str, Any]) -> float:
    slug = _module_slug(module_path)
    base = _MODULE_CONFIDENCE.get(slug, 0.68)
    if isinstance(details, Mapping):
        if details.get("error"):
            return min(base, 0.35)
        if details.get("skipped"):
            return min(base, 0.40)
        risk = details.get("risk_score")
        if isinstance(risk, (int, float)) and risk >= 60:
            base = min(0.95, base + 0.05)
        findings = details.get("findings")
        if isinstance(findings, list) and findings:
            confidences = [
                float(f.get("confidence", 0)) / 100.0
                for f in findings
                if isinstance(f, dict) and f.get("confidence") is not None
            ]
            if confidences:
                base = max(base, sum(confidences) / len(confidences))
    return round(min(0.99, max(0.1, base)), 3)


def infer_source_urls(module_path: str, details: Mapping[str, Any], target: str = "") -> List[str]:
    urls: List[str] = []
    slug = _module_slug(module_path)
    target = str(target or details.get("target") or "").strip()

    if slug == "domain_surface_mapper" and target:
        urls.append(f"https://crt.sh/?q=%25.{target}&output=json")
        urls.append(f"https://rdap.org/domain/{target}")
    elif slug == "domain_crtsh" and target:
        urls.append(f"https://crt.sh/?q=%25.{target}&output=json")
    elif slug == "passive_dns_aggregator" and target:
        urls.append(f"https://crt.sh/?q=%25.{target}&output=json")
    elif slug == "reverse_whois_org_mapper":
        query = str(details.get("query") or target or "").strip()
        if query:
            urls.append(f"https://api.hackertarget.com/reversewhois/?q={query}")
            urls.append(f"https://rdap.org/entity?name={query}")
    elif slug == "wayback_surface_hunter" and target:
        urls.append(f"https://web.archive.org/cdx/search/cdx?url={target}/*&output=json")
    elif slug == "github_org_exposure" and target:
        org = target.split(".", 1)[0]
        urls.append(f"https://api.github.com/orgs/{org}/repos")

    if isinstance(details, Mapping):
        for finding in details.get("findings") or []:
            if not isinstance(finding, dict):
                continue
            for key in ("url", "source_url", "profile", "archive_url"):
                val = str(finding.get(key) or "").strip()
                if val.startswith(("http://", "https://")):
                    urls.append(val)
        for check in details.get("http_checks") or []:
            if isinstance(check, dict):
                for key in ("url", "final_url"):
                    val = str(check.get(key) or "").strip()
                    if val.startswith(("http://", "https://")):
                        urls.append(val)

    seen: set = set()
    out: List[str] = []
    for url in urls:
        if url not in seen:
            seen.add(url)
            out.append(url)
    return out[:24]


def envelope_osint_details(
    details: Mapping[str, Any],
    *,
    module_path: str,
    target: str = "",
    collected_at: Optional[str] = None,
) -> Dict[str, Any]:
    if not isinstance(details, Mapping):
        details = {}
    stamped = dict(details)
    ts = collected_at or utc_now_z()
    confidence = infer_osint_confidence(module_path, stamped)
    sources = infer_source_urls(module_path, stamped, target=target)
    digest = content_sha256(stamped)

    stamped.setdefault("collected_at", ts)
    stamped.setdefault("confidence", confidence)
    stamped.setdefault("source_urls", sources)
    stamped.setdefault("content_sha256", digest)
    stamped["_osint_meta"] = {
        "module_path": module_path,
        "collected_at": ts,
        "confidence": confidence,
        "source_urls": sources,
        "content_sha256": digest,
        "schema_version": SCHEMA_VERSION,
    }
    return stamped


def envelope_module_result_row(row: Mapping[str, Any]) -> Dict[str, Any]:
    """Normalize an agent/workflow OSINT result row with evidence metadata."""
    if not isinstance(row, Mapping):
        return {}
    out = dict(row)
    path = str(out.get("path") or "")
    target = str(out.get("target") or "")
    details = out.get("details")
    if not isinstance(details, dict):
        details = {}
    if isinstance(out.get("message"), str) and out["message"] and "error" not in details:
        details.setdefault("message", out["message"])
    out["details"] = envelope_osint_details(details, module_path=path, target=target)
    out["collected_at"] = out["details"].get("collected_at")
    out["confidence"] = out["details"].get("confidence")
    out["source_urls"] = out["details"].get("source_urls")
    return out


def module_result_to_evidence_records(
    row: Mapping[str, Any],
    *,
    run_id: str = "",
    actor: str = "agent",
    legal_basis: str = "",
) -> List[Dict[str, Any]]:
    """Build json/v1 Evidence dicts from an OSINT module result row."""
    path = str(row.get("path") or "")
    if _OSINT_MODULE_PREFIX not in path:
        return []

    details = row.get("details") if isinstance(row.get("details"), dict) else {}
    target = str(row.get("target") or details.get("target") or "")
    collected_at = str(row.get("collected_at") or details.get("collected_at") or utc_now_z())
    confidence = row.get("confidence") or details.get("confidence") or infer_osint_confidence(path, details)
    digest = str(details.get("content_sha256") or content_sha256(details))
    module_name = str(row.get("module") or _module_slug(path) or "osint")

    summary_parts = [str(row.get("message") or "").strip()]
    if details.get("risk_level"):
        summary_parts.append(f"risk={details.get('risk_level')}")
    summary = " | ".join(part for part in summary_parts if part)[:4000] or f"OSINT collection from {module_name}"

    record: Dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "id": f"ev_osint_{digest[:12]}",
        "kind": "artifact",
        "title": f"OSINT: {module_name}",
        "summary": summary,
        "collected_at": collected_at,
        "target": target or None,
        "source": {"name": path, "type": "module"},
        "module": {"path": path, "name": module_name, "type": "auxiliary"},
        "confidence": confidence,
        "tags": ["osint", "passive"],
        "artifact": {
            "path": str(details.get("output_file") or ""),
            "sha256": digest,
            "mime_type": "application/json",
        },
        "metadata": {
            "run_id": run_id,
            "legal_basis": legal_basis,
            "source_urls": list(row.get("source_urls") or details.get("source_urls") or []),
            "status": str(row.get("status") or ""),
        },
        "chain_of_custody": [
            {
                "actor": actor,
                "action": "collected",
                "at": collected_at,
                "digest_sha256": digest,
                "notes": f"OSINT module {path}",
            }
        ],
    }
    return [record]


class OsintEvidenceCollector:
    """Hash-chained collector for OSINT module outputs and synthesis."""

    def __init__(
        self,
        run_id: str,
        *,
        policy_hash: str = "",
        legal_basis: str = "",
        actor: str = "agent",
    ) -> None:
        self.run_id = run_id
        self.legal_basis = legal_basis
        self.actor = actor
        ledger_cls = _load_evidence_ledger_class()
        self.ledger = ledger_cls(run_id, policy_hash=policy_hash)
        self.evidence_records: List[Dict[str, Any]] = []
        self.module_results: List[Dict[str, Any]] = []

    def record_module_result(self, row: Mapping[str, Any]) -> Dict[str, Any]:
        enveloped = envelope_module_result_row(row)
        self.module_results.append(enveloped)
        path = str(enveloped.get("path") or "")
        target = str(enveloped.get("target") or enveloped.get("details", {}).get("target") or "")
        digest = str((enveloped.get("details") or {}).get("content_sha256") or content_sha256(enveloped.get("details")))

        self.ledger.append(
            "osint_module",
            {
                "module_path": path,
                "target": target,
                "status": enveloped.get("status"),
                "confidence": enveloped.get("confidence"),
                "content_sha256": digest,
                "legal_basis": self.legal_basis,
            },
            module=path,
            target=target,
        )
        for record in module_result_to_evidence_records(
            enveloped,
            run_id=self.run_id,
            actor=self.actor,
            legal_basis=self.legal_basis,
        ):
            self.evidence_records.append(record)
        return enveloped

    def record_synthesis(self, synthesis: Mapping[str, Any]) -> Dict[str, Any]:
        payload = dict(synthesis) if isinstance(synthesis, Mapping) else {}
        digest = content_sha256(payload)
        entry = self.ledger.append(
            "osint_synthesis",
            {
                "node_count": payload.get("node_count"),
                "edge_count": payload.get("edge_count"),
                "root_domain": payload.get("root_domain"),
                "content_sha256": digest,
                "legal_basis": self.legal_basis,
            },
            module="core/osint/intel_synthesis",
            target=str(payload.get("root_domain") or ""),
        )
        return entry

    def verify(self) -> bool:
        return self.ledger.verify()

    def persist(self, output_dir: Path) -> Dict[str, str]:
        output_dir.mkdir(parents=True, exist_ok=True)
        paths: Dict[str, str] = {}

        ledger_path = output_dir / "osint_evidence_ledger.json"
        ledger_payload = {
            "run_id": self.run_id,
            "legal_basis": self.legal_basis,
            "verified": self.verify(),
            "entries": self.ledger.to_list(),
        }
        ledger_path.write_text(json.dumps(ledger_payload, indent=2), encoding="utf-8")
        paths["ledger"] = str(ledger_path)

        evidence_path = output_dir / "osint_evidence_records.json"
        evidence_path.write_text(json.dumps(self.evidence_records, indent=2), encoding="utf-8")
        paths["evidence"] = str(evidence_path)

        results_path = output_dir / "osint_module_results.json"
        results_path.write_text(json.dumps(self.module_results, indent=2), encoding="utf-8")
        paths["results"] = str(results_path)

        return paths
