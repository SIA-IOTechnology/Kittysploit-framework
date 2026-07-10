#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""OPSEC audit journal for OSINT investigations (compartmentation + passive-only guard)."""

from __future__ import annotations

import hashlib
import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from core.osint.config import get_osint_config
from core.osint.evidence import utc_now_z

_PASSIVE_ALLOWED_PREFIX = "auxiliary/osint/"
_PASSIVE_BLOCK_TOKENS = (
    "bruteforce",
    "persona_password",
    "admin_login",
    "exploit/",
    "exploits/",
    "payload",
    "listener",
    "auxiliary/scanner/",
    "scanner/",
    "write_coil",
    "dos/",
)


def _target_fingerprint(value: str) -> str:
    text = str(value or "").strip().lower()
    if not text:
        return ""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]


@dataclass
class OsintOpsecJournal:
    """Append-only audit log for OSINT operator actions."""

    workspace: str = "default"
    case_id: str = ""
    legal_basis: str = ""
    operator: str = ""
    passive_only: bool = True
    audit_path: Optional[Path] = None
    entries: List[Dict[str, Any]] = field(default_factory=list)

    def __post_init__(self) -> None:
        if self.audit_path is None:
            base = Path(get_osint_config().audit_dir())
            self.audit_path = base / "audit.jsonl"
        if not self.operator:
            import os
            self.operator = os.environ.get("USER", os.environ.get("USERNAME", "operator"))

    def check_passive_violation(self, module_path: str) -> Optional[str]:
        path = str(module_path or "").strip().lower()
        if not self.passive_only:
            return None
        if path.startswith(_PASSIVE_ALLOWED_PREFIX):
            return None
        if any(token in path for token in _PASSIVE_BLOCK_TOKENS):
            return f"passive-only policy blocks module: {module_path}"
        if path.startswith(("exploit/", "post/", "payloads/", "listeners/")):
            return f"passive-only policy blocks offensive module: {module_path}"
        return f"passive-only policy allows only auxiliary/osint modules, got: {module_path}"

    def record(
        self,
        *,
        action: str,
        module: str = "",
        target: str = "",
        status: str = "ok",
        details: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        violation = self.check_passive_violation(module) if module else None
        record = {
            "timestamp": utc_now_z(),
            "action": action,
            "module": module,
            "target_fingerprint": _target_fingerprint(target),
            "status": "blocked" if violation else status,
            "workspace": self.workspace,
            "case_id": self.case_id,
            "legal_basis": self.legal_basis,
            "operator": self.operator,
            "passive_only": self.passive_only,
            "violation": violation,
            "details": details or {},
        }
        self.entries.append(record)
        self._append_file(record)
        return record

    def record_compartmentation_check(
        self,
        *,
        current_workspace: str,
        prior_workspace: str,
    ) -> bool:
        """Return False if workspace switch may indicate compartmentation breach."""
        ok = str(current_workspace) == str(prior_workspace) or not prior_workspace
        self.record(
            action="compartmentation_check",
            status="ok" if ok else "warning",
            details={
                "current_workspace": current_workspace,
                "prior_workspace": prior_workspace,
                "isolated": ok,
            },
        )
        return ok

    def record_provider_access(
        self,
        *,
        provider: str,
        module: str,
        authenticated: bool,
        target: str = "",
    ) -> None:
        self.record(
            action="provider_access",
            module=module,
            target=target,
            details={
                "provider": provider,
                "authenticated": authenticated,
            },
        )

    def summarize(self) -> Dict[str, Any]:
        blocked = sum(1 for e in self.entries if e.get("status") == "blocked")
        warnings = sum(1 for e in self.entries if e.get("status") == "warning")
        return {
            "entry_count": len(self.entries),
            "blocked_count": blocked,
            "warning_count": warnings,
            "passive_only": self.passive_only,
            "audit_path": str(self.audit_path),
        }

    def persist_session_log(self, output_dir: Path) -> str:
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        path = output_dir / "osint_opsec_audit.jsonl"
        with open(path, "w", encoding="utf-8") as handle:
            for entry in self.entries:
                handle.write(json.dumps(entry, ensure_ascii=False) + "\n")
        summary_path = output_dir / "osint_opsec_summary.json"
        summary_path.write_text(json.dumps(self.summarize(), indent=2), encoding="utf-8")
        return str(path)

    def _append_file(self, record: Dict[str, Any]) -> None:
        try:
            self.audit_path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.audit_path, "a", encoding="utf-8") as handle:
                handle.write(json.dumps(record, ensure_ascii=False) + "\n")
        except OSError:
            pass


def sanitize_opsec_log_text(text: str, max_len: int = 240) -> str:
    """Redact obvious secrets from log snippets."""
    cleaned = str(text or "")
    cleaned = re.sub(r"(?i)(api[_-]?key|token|secret|password)\s*[:=]\s*\S+", r"\1=[REDACTED]", cleaned)
    return cleaned[:max_len]
