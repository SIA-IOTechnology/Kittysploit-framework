#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""GDPR-aware retention, pseudonymization, and export redaction for OSINT data."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Mapping, MutableMapping, Optional, Sequence

from core.osint.config import get_osint_config


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _parse_ts(value: str) -> Optional[datetime]:
    text = str(value or "").strip()
    if not text:
        return None
    try:
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        return datetime.fromisoformat(text)
    except ValueError:
        return None


@dataclass
class OsintRetentionPolicy:
    """Configurable retention windows (days) per OSINT data category."""

    pii_days: int = 90
    ioc_days: int = 365
    audit_days: int = 730
    legal_basis_required: bool = True
    pseudonymize_exports: bool = True
    data_controller: str = ""
    processing_purpose: str = "law_enforcement_osint_investigation"
    lawful_basis_article: str = "Art. 6(1)(e) GDPR — public interest / official authority"

    @classmethod
    def from_mapping(cls, data: Optional[Mapping[str, Any]]) -> "OsintRetentionPolicy":
        if not isinstance(data, Mapping):
            return cls.from_osint_config()
        general = get_osint_config().get_section("general")
        return cls(
            pii_days=int(data.get("pii_days") or data.get("retention_days") or 90),
            ioc_days=int(data.get("ioc_days") or 365),
            audit_days=int(data.get("audit_days") or 730),
            legal_basis_required=bool(data.get("legal_basis_required", True)),
            pseudonymize_exports=bool(data.get("pseudonymize_exports", True)),
            data_controller=str(data.get("data_controller") or general.get("data_controller") or ""),
            processing_purpose=str(data.get("processing_purpose") or "law_enforcement_osint_investigation"),
            lawful_basis_article=str(data.get("lawful_basis_article") or "Art. 6(1)(e) GDPR — public interest / official authority"),
        )

    @classmethod
    def from_osint_config(cls) -> "OsintRetentionPolicy":
        """Build policy defaults from ``osint.toml`` [gdpr] and [general]."""
        cfg = get_osint_config()
        gdpr = cfg.gdpr_defaults()
        general = cfg.get_section("general")
        if not gdpr:
            return cls(data_controller=str(general.get("data_controller") or ""))
        return cls.from_mapping({**gdpr, "data_controller": general.get("data_controller", "")})

    def expiry_iso(self, category: str, *, from_ts: Optional[datetime] = None) -> str:
        start = from_ts or _utc_now()
        days = {
            "pii": self.pii_days,
            "ioc": self.ioc_days,
            "audit": self.audit_days,
        }.get(category, self.ioc_days)
        return (start + timedelta(days=max(1, days))).replace(microsecond=0).isoformat().replace("+00:00", "Z")


_EMAIL_RE = re.compile(r"^[^@]+@[^@]+\.[^@]+$")


def pseudonymize_email(email: str, *, salt: str = "") -> str:
    text = str(email or "").strip().lower()
    if not _EMAIL_RE.match(text):
        return text
    local, domain = text.split("@", 1)
    digest = hashlib.sha256(f"{salt}:{text}".encode()).hexdigest()[:10]
    return f"{local[0]}***.{digest}@{domain}"


def pseudonymize_name(name: str, *, salt: str = "") -> str:
    text = str(name or "").strip()
    if not text:
        return text
    parts = text.split()
    if len(parts) >= 2:
        return f"{parts[0][0]}. {parts[-1][0]}***"
    digest = hashlib.sha256(f"{salt}:{text}".encode()).hexdigest()[:6]
    return f"subject-{digest}"


def build_gdpr_metadata(
    policy: OsintRetentionPolicy,
    *,
    case_id: str = "",
    legal_basis: str = "",
    generated_at: str = "",
) -> Dict[str, Any]:
    ts = _parse_ts(generated_at) or _utc_now()
    return {
        "regulation": "GDPR",
        "data_controller": policy.data_controller,
        "processing_purpose": policy.processing_purpose,
        "lawful_basis": policy.lawful_basis_article,
        "legal_basis_reference": legal_basis,
        "case_id": case_id,
        "retention": {
            "pii_expires_at": policy.expiry_iso("pii", from_ts=ts),
            "ioc_expires_at": policy.expiry_iso("ioc", from_ts=ts),
            "audit_expires_at": policy.expiry_iso("audit", from_ts=ts),
            "pii_days": policy.pii_days,
            "ioc_days": policy.ioc_days,
            "audit_days": policy.audit_days,
        },
        "pseudonymize_exports": policy.pseudonymize_exports,
        "subject_rights_note": (
            "Data subjects may exercise access/erasure rights per national LE exemptions; "
            "erase PII artifacts when no longer required for the investigation."
        ),
    }


def redact_pii_in_structure(
    obj: Any,
    *,
    case_id: str = "",
    policy: Optional[OsintRetentionPolicy] = None,
) -> Any:
    """Recursively pseudonymize emails and person names in export structures."""
    policy = policy or OsintRetentionPolicy()
    if not policy.pseudonymize_exports:
        return obj
    salt = case_id or "osint"

    if isinstance(obj, dict):
        out: Dict[str, Any] = {}
        for key, value in obj.items():
            kl = str(key).lower()
            if kl in ("email", "email-src") and isinstance(value, str):
                out[key] = pseudonymize_email(value, salt=salt)
            elif kl in ("person", "persona", "persona_seed", "full_name", "name") and isinstance(value, str):
                if "@" not in value:
                    out[key] = pseudonymize_name(value, salt=salt)
                else:
                    out[key] = pseudonymize_email(value, salt=salt)
            elif kl == "emails" and isinstance(value, list):
                out[key] = [pseudonymize_email(v, salt=salt) if isinstance(v, str) else v for v in value]
            else:
                out[key] = redact_pii_in_structure(value, case_id=case_id, policy=policy)
        return out
    if isinstance(obj, list):
        return [redact_pii_in_structure(item, case_id=case_id, policy=policy) for item in obj]
    if isinstance(obj, str) and _EMAIL_RE.match(obj.strip()):
        return pseudonymize_email(obj, salt=salt)
    return obj


def apply_gdpr_to_bundle_manifest(
    manifest: MutableMapping[str, Any],
    policy: OsintRetentionPolicy,
    *,
    case_id: str = "",
    legal_basis: str = "",
) -> Dict[str, Any]:
    """Attach GDPR block to manifest and validate legal basis when required."""
    generated = str(manifest.get("generated_at") or "")
    gdpr = build_gdpr_metadata(policy, case_id=case_id, legal_basis=legal_basis, generated_at=generated)
    manifest["gdpr"] = gdpr
    if policy.legal_basis_required and not str(legal_basis or "").strip():
        manifest["gdpr_warning"] = "legal_basis missing — LE processing should record mandate/warrant reference"
    return dict(manifest)


def write_gdpr_sidecar(output_dir: Path, gdpr_metadata: Mapping[str, Any]) -> str:
    path = Path(output_dir) / "gdpr_retention.json"
    path.write_text(json.dumps(dict(gdpr_metadata), indent=2), encoding="utf-8")
    return str(path)


def purge_expired_artifacts(
    bundle_dir: Path,
    *,
    policy: Optional[OsintRetentionPolicy] = None,
    dry_run: bool = True,
) -> List[str]:
    """
    Remove PII-heavy artifacts past retention based on ``gdpr_retention.json``.

    Always preserves audit ledger and manifest skeleton when dry_run=False.
    """
    bundle_dir = Path(bundle_dir)
    policy = policy or OsintRetentionPolicy()
    sidecar = bundle_dir / "gdpr_retention.json"
    if not sidecar.is_file():
        return []

    try:
        meta = json.loads(sidecar.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []

    retention = meta.get("retention") if isinstance(meta.get("retention"), dict) else {}
    pii_expires = _parse_ts(str(retention.get("pii_expires_at") or ""))
    if not pii_expires or _utc_now() < pii_expires:
        return []

    pii_files = [
        "osint_report_operational.json",
        "osint_module_results.json",
        "osint_evidence_records.json",
    ]
    removed: List[str] = []
    for name in pii_files:
        path = bundle_dir / name
        if not path.is_file():
            continue
        if dry_run:
            removed.append(f"would_remove:{path}")
        else:
            try:
                path.unlink()
                removed.append(str(path))
            except OSError:
                pass
    return removed
