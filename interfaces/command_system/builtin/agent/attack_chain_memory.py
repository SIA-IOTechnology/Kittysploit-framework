#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Stateful attack chains via memory poisoning and outcome observations.

Each successful module step can **poison** the campaign knowledge base with
structured capabilities (session cookies, log paths, upload dirs, etc.).
Downstream modules declare ``agent.chain.consumes_capabilities`` and
``option_bindings`` so the planner can chain stateful follow-ups and pre-fill
module options from poisoned memory — without storing raw secrets in the poison
store when redaction applies.

Each executed module also records a compact observation (``confirmed``,
``refuted``, ``blocked``, ``error`` or ``no_signal``). These observations let the
planner avoid repeating noisy or blocked branches while still keeping positive
capabilities available for chaining.

Persisted on the in-memory KB under ``attack_chain_memory``::

    {
      "version": 2,
      "entries": [
        {
          "id": "a1b2",
          "capability": "log_file_path",
          "value": "/var/log/apache2/access.log",
          "source_module": "scanner/http/lfi_detect",
          "confidence": 0.82,
          "redacted": false
        }
      ],
      "observations": [
        {
          "module_path": "auxiliary/scanner/http/ssrf_cloud_metadata_harvest",
          "status": "refuted",
          "capability": "ssrf_primitive",
          "reason": "No cloud metadata retrieved"
        }
      ],
      "chain_ids": ["a1b2", "c3d4"]
    }
"""

from __future__ import annotations

import hashlib
import logging
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Mapping, MutableMapping, Optional, Set

from .chain_meta import normalize_chain_block

try:
    from interfaces.command_system.builtin.agent.redaction import redact_text
except Exception:  # pragma: no cover - import guard for isolated tests
    def redact_text(value: Any, limit: int = 16000) -> str:
        return str(value or "")[: max(0, int(limit))]

try:
    from interfaces.command_system.builtin.agent.chain_context import enrich_result_details_for_chain
except Exception:  # pragma: no cover - import guard for minimal test envs
    def enrich_result_details_for_chain(result: Mapping[str, Any]) -> Dict[str, Any]:
        return dict(result) if isinstance(result, Mapping) else {}

logger = logging.getLogger(__name__)

MEMORY_KEY = "attack_chain_memory"
MEMORY_VERSION = 2
MAX_ENTRIES = 96
MAX_CHAIN_IDS = 48
MAX_OBSERVATIONS = 192
MAX_VALUE_LEN = 4096
MAX_PROOF_LEN = 420

OBS_CONFIRMED = "confirmed"
OBS_REFUTED = "refuted"
OBS_BLOCKED = "blocked"
OBS_ERROR = "error"
OBS_NO_SIGNAL = "no_signal"
NEGATIVE_OBSERVATION_STATUSES: frozenset[str] = frozenset({
    OBS_REFUTED,
    OBS_BLOCKED,
    OBS_ERROR,
    OBS_NO_SIGNAL,
})

KNOWN_CAPABILITIES: frozenset[str] = frozenset({
    "credentials",
    "session_cookie",
    "authenticated_session",
    "auth_bypass",
    "csrf_token",
    "file_read",
    "log_file_path",
    "poisoned_payload",
    "upload_path",
    "db_access",
    "inj_param",
    "inj_path",
    "inj_method",
    "lfi_param",
    "landing_path",
    "cookie_header",
    "rce",
    "shell",
    "root",
    "admin_access",
    "cloud_credentials",
    "cloud_identity",
    "ldap_access",
    "kerberoast_targets",
    "asrep_targets",
    "ssrf_primitive",
    "ssrf_param",
    "ssrf_method",
    "graphql_endpoint",
    "dnp3_access",
    "dnp3_dest",
    "ot_assets",
    "login_paths",
    "modbus_tcp",
    "s7comm",
    "iec104_access",
    "mysql_access",
    "postgres_access",
    "mssql_access",
    "redis_access",
    "smb_access",
    "ssh_access",
    "winrm_access",
    "service_identified",
    "share_list",
    "tech_hints",
    "endpoints",
    "file_upload",
    "java_vuln_signal",
    "adcs_surface",
    "container_admin",
    "misconfig_surface",
    "ai_panel",
    "unauth_read",
    "unauth_write",
    "enterprise_panel",
    "admin_surface",
    "network_service",
    "adcs_misconfig",
    "cloud_exposure",
    "cve_indicator",
    "deserialization",
    "devops_panel",
    "file_delete",
    "file_write",
    "identity_surface",
    "k8s_misconfig",
    "native_vlan",
    "network_device",
    "openapi_spec",
    "remote_access",
    "target_vlan",
    "uart_traffic",
    "vlan_access",
    "vlan_segment",
    "vpn_access",
    "web_session",
})

# Maps heuristic signals / detail keys → capability tokens.
_HEURISTIC_DETAIL_KEYS: Dict[str, str] = {
    "log_path": "log_file_path",
    "log_file": "log_file_path",
    "access_log": "log_file_path",
    "upload_path": "upload_path",
    "upload_dir": "upload_path",
    "target_path": "file_read",
    "lfi_path": "file_read",
    "session_cookie": "session_cookie",
    "cookie": "session_cookie",
    "cookie_header": "cookie_header",
    "csrf_token": "csrf_token",
    "database": "db_access",
    "db_name": "db_access",
    "inj_param": "inj_param",
    "inj_path": "inj_path",
    "inj_method": "inj_method",
    "ssrf_param": "ssrf_param",
    "graphql_path": "graphql_endpoint",
    "graphql_endpoint": "graphql_endpoint",
    "dest_address": "dnp3_dest",
    "lfi_param": "lfi_param",
    "lfi_path": "file_read",
    "landing_path": "landing_path",
    "post_login_final_path": "landing_path",
    "poison_payload": "poisoned_payload",
}

_LOG_PATH_RE = re.compile(
    r"(/var/log/[^\s\"']+|/proc/self/[^\s\"']+|/etc/passwd)",
    re.IGNORECASE,
)

_BLOCKED_RE = re.compile(
    r"\b(waf|blocked|forbidden|captcha|rate.?limit|too many requests|403|429|honeypot)\b",
    re.IGNORECASE,
)
_REFUTED_RE = re.compile(
    r"\b(not vulnerable|no valid|no credential|not detected|found: 0|no match|not exploitable|"
    r"lfi not confirmed|ssrf not confirmed|no cloud metadata|no command execution|"
    r"attempts exhausted|failed after|exhausted|could not find)\b",
    re.IGNORECASE,
)
_ERROR_RE = re.compile(
    r"\b(error|exception|timeout|timed out|connection refused|unreachable|failed)\b",
    re.IGNORECASE,
)


def _now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


@dataclass
class PoisonEntry:
    capability: str
    value: str
    source_module: str = ""
    phase: str = ""
    confidence: float = 0.75
    redacted: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)
    entry_id: str = ""

    def __post_init__(self) -> None:
        self.capability = str(self.capability or "").strip().lower()
        self.value = str(self.value or "").strip()[:MAX_VALUE_LEN]
        if not self.entry_id:
            digest = hashlib.sha256(
                f"{self.capability}:{self.value}:{self.source_module}".encode("utf-8", "ignore")
            ).hexdigest()
            self.entry_id = digest[:12]
        try:
            self.confidence = max(0.0, min(1.0, float(self.confidence)))
        except (TypeError, ValueError):
            self.confidence = 0.75

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ChainObservation:
    module_path: str
    status: str
    capability: str = ""
    value: str = ""
    phase: str = ""
    confidence: float = 0.5
    proof_summary: str = ""
    reason: str = ""
    target: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)
    observation_id: str = ""
    count: int = 1
    created_at: str = ""
    last_seen: str = ""

    def __post_init__(self) -> None:
        self.module_path = str(self.module_path or "").strip()[:300]
        self.status = str(self.status or OBS_NO_SIGNAL).strip().lower()
        if self.status not in {
            OBS_CONFIRMED,
            OBS_REFUTED,
            OBS_BLOCKED,
            OBS_ERROR,
            OBS_NO_SIGNAL,
        }:
            self.status = OBS_NO_SIGNAL
        self.capability = str(self.capability or "").strip().lower()
        self.value = str(self.value or "").strip()[:MAX_VALUE_LEN]
        self.phase = str(self.phase or "").strip()[:80]
        self.proof_summary = redact_text(self.proof_summary, MAX_PROOF_LEN)
        self.reason = redact_text(self.reason, 220)
        self.target = redact_text(self.target, 220)
        try:
            self.confidence = max(0.0, min(1.0, float(self.confidence)))
        except (TypeError, ValueError):
            self.confidence = 0.5
        try:
            self.count = max(1, int(self.count))
        except (TypeError, ValueError):
            self.count = 1
        now = _now_iso()
        if not self.created_at:
            self.created_at = now
        if not self.last_seen:
            self.last_seen = self.created_at
        if not self.observation_id:
            digest = hashlib.sha256(
                (
                    f"{self.module_path}:{self.status}:{self.capability}:"
                    f"{self.value}:{self.reason}"
                ).encode("utf-8", "ignore")
            ).hexdigest()
            self.observation_id = digest[:12]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def _empty_memory() -> Dict[str, Any]:
    return {
        "version": MEMORY_VERSION,
        "entries": [],
        "observations": [],
        "chain_ids": [],
    }


def get_memory(kb: Mapping[str, Any]) -> Dict[str, Any]:
    raw = kb.get(MEMORY_KEY) if isinstance(kb, Mapping) else None
    if not isinstance(raw, dict):
        return _empty_memory()
    entries = raw.get("entries")
    observations = raw.get("observations")
    chain_ids = raw.get("chain_ids")
    return {
        "version": int(raw.get("version", MEMORY_VERSION) or MEMORY_VERSION),
        "entries": list(entries) if isinstance(entries, list) else [],
        "observations": list(observations) if isinstance(observations, list) else [],
        "chain_ids": list(chain_ids) if isinstance(chain_ids, list) else [],
    }


def _capability_values(kb: Mapping[str, Any], capability: str) -> List[str]:
    cap = capability.strip().lower()
    values: List[str] = []
    for entry in get_memory(kb).get("entries", []):
        if not isinstance(entry, dict):
            continue
        if str(entry.get("capability", "")).lower() != cap:
            continue
        val = str(entry.get("value", "") or "").strip()
        if val and val not in values:
            values.append(val)
    return values


def best_capability_value(kb: Mapping[str, Any], capability: str) -> str:
    """Return the highest-confidence poison value for a capability, if any."""
    cap = capability.strip().lower()
    best = ""
    best_conf = -1.0
    for entry in get_memory(kb).get("entries", []):
        if not isinstance(entry, dict):
            continue
        if str(entry.get("capability", "")).lower() != cap:
            continue
        try:
            conf = float(entry.get("confidence", 0.0) or 0.0)
        except (TypeError, ValueError):
            conf = 0.0
        val = str(entry.get("value", "") or "").strip()
        if val and conf >= best_conf:
            best = val
            best_conf = conf
    return best


def capabilities_present(kb: Mapping[str, Any]) -> Set[str]:
    present: Set[str] = set()
    for entry in get_memory(kb).get("entries", []):
        if isinstance(entry, dict):
            cap = str(entry.get("capability", "")).strip().lower()
            if cap:
                present.add(cap)
    for cap in kb.get("unlocked_capabilities", []) or []:
        if str(cap).strip():
            present.add(str(cap).strip().lower())
    return present


def capabilities_satisfied(
    kb: Mapping[str, Any],
    required_any: Iterable[str],
    required_all: Iterable[str],
) -> bool:
    present = capabilities_present(kb)
    need_all = [str(x).strip().lower() for x in required_all if str(x).strip()]
    if need_all and not all(x in present for x in need_all):
        return False
    need_any = [str(x).strip().lower() for x in required_any if str(x).strip()]
    if need_any and not any(x in present for x in need_any):
        return False
    return True


def _merge_entry(entries: List[Dict[str, Any]], new_entry: PoisonEntry) -> None:
    for existing in entries:
        if not isinstance(existing, dict):
            continue
        if (
            existing.get("capability") == new_entry.capability
            and existing.get("value") == new_entry.value
        ):
            try:
                old_conf = float(existing.get("confidence", 0.0) or 0.0)
            except (TypeError, ValueError):
                old_conf = 0.0
            existing["confidence"] = round(max(old_conf, new_entry.confidence), 3)
            if new_entry.source_module:
                existing["source_module"] = new_entry.source_module
            return
    entries.append(new_entry.to_dict())
    if len(entries) > MAX_ENTRIES:
        del entries[:-MAX_ENTRIES]


def _merge_observation(observations: List[Dict[str, Any]], new_observation: ChainObservation) -> None:
    for existing in observations:
        if not isinstance(existing, dict):
            continue
        if existing.get("observation_id") == new_observation.observation_id:
            try:
                old_conf = float(existing.get("confidence", 0.0) or 0.0)
            except (TypeError, ValueError):
                old_conf = 0.0
            existing["confidence"] = round(max(old_conf, new_observation.confidence), 3)
            existing["last_seen"] = _now_iso()
            try:
                existing["count"] = max(1, int(existing.get("count", 1) or 1)) + 1
            except (TypeError, ValueError):
                existing["count"] = 2
            if new_observation.proof_summary:
                existing["proof_summary"] = new_observation.proof_summary
            if new_observation.reason:
                existing["reason"] = new_observation.reason
            return
    observations.append(new_observation.to_dict())
    if len(observations) > MAX_OBSERVATIONS:
        del observations[:-MAX_OBSERVATIONS]


def apply_poisons_to_kb(kb: MutableMapping[str, Any], poisons: List[PoisonEntry]) -> None:
    """Merge poison entries into ``kb[attack_chain_memory]`` and sync capabilities."""
    if not isinstance(kb, MutableMapping) or not poisons:
        return
    memory = get_memory(kb)
    entries: List[Dict[str, Any]] = list(memory.get("entries") or [])
    chain_ids: List[str] = list(memory.get("chain_ids") or [])
    for poison in poisons:
        if not poison.capability or not poison.value:
            continue
        if poison.capability not in KNOWN_CAPABILITIES:
            continue
        _merge_entry(entries, poison)
        if poison.entry_id and poison.entry_id not in chain_ids:
            chain_ids.append(poison.entry_id)
    if len(chain_ids) > MAX_CHAIN_IDS:
        chain_ids = chain_ids[-MAX_CHAIN_IDS:]
    kb[MEMORY_KEY] = {
        "version": MEMORY_VERSION,
        "entries": entries,
        "observations": memory.get("observations") or [],
        "chain_ids": chain_ids,
    }
    sync_unlocked_capabilities(kb)


def apply_observations_to_kb(
    kb: MutableMapping[str, Any],
    observations: List[ChainObservation],
) -> None:
    """Merge positive/negative run observations into ``kb[attack_chain_memory]``."""
    if not isinstance(kb, MutableMapping) or not observations:
        return
    memory = get_memory(kb)
    rows: List[Dict[str, Any]] = list(memory.get("observations") or [])
    for observation in observations:
        if not observation.module_path:
            continue
        _merge_observation(rows, observation)
    kb[MEMORY_KEY] = {
        "version": MEMORY_VERSION,
        "entries": list(memory.get("entries") or []),
        "observations": rows,
        "chain_ids": list(memory.get("chain_ids") or []),
    }


def get_observations(
    kb: Mapping[str, Any],
    *,
    statuses: Optional[Iterable[str]] = None,
    module_path: str = "",
    capability: str = "",
) -> List[Dict[str, Any]]:
    """Return filtered chain observations from memory."""
    memory = get_memory(kb if isinstance(kb, Mapping) else {})
    wanted_statuses = {
        str(status).strip().lower()
        for status in (statuses or [])
        if str(status).strip()
    }
    path_l = str(module_path or "").strip().lower()
    cap_l = str(capability or "").strip().lower()
    rows: List[Dict[str, Any]] = []
    for row in memory.get("observations") or []:
        if not isinstance(row, dict):
            continue
        if wanted_statuses and str(row.get("status", "")).lower() not in wanted_statuses:
            continue
        if path_l and str(row.get("module_path", "")).lower() != path_l:
            continue
        if cap_l and str(row.get("capability", "")).lower() != cap_l:
            continue
        rows.append(row)
    return rows


def sync_unlocked_capabilities(kb: MutableMapping[str, Any]) -> None:
    """Mirror poison capabilities into ``unlocked_capabilities`` for the action planner."""
    caps = {str(c).strip().lower() for c in kb.get("unlocked_capabilities", []) or [] if str(c).strip()}
    for cap in capabilities_present(kb):
        if cap in KNOWN_CAPABILITIES:
            caps.add(cap)
    kb["unlocked_capabilities"] = sorted(caps)


def _heuristic_poisons_from_result(module_path: str, result: Mapping[str, Any]) -> List[PoisonEntry]:
    poisons: List[PoisonEntry] = []
    if not isinstance(result, Mapping):
        return poisons
    details = result.get("details") or {}
    msg = str(result.get("message", "") or "")
    blob = msg
    mod_low = str(module_path or result.get("path", "") or "").lower()
    vulnerable = bool(result.get("vulnerable"))

    if isinstance(details, dict):
        for key, cap in _HEURISTIC_DETAIL_KEYS.items():
            val = details.get(key)
            if isinstance(val, str) and val.strip():
                poisons.append(PoisonEntry(
                    capability=cap,
                    value=val.strip(),
                    source_module=module_path,
                    confidence=0.88 if vulnerable else 0.62,
                ))
        blob += " " + " ".join(str(v) for v in details.values() if isinstance(v, str))

    for match in _LOG_PATH_RE.findall(blob):
        poisons.append(PoisonEntry(
            capability="log_file_path",
            value=match,
            source_module=module_path,
            confidence=0.8 if vulnerable else 0.55,
        ))

    if vulnerable:
        if any(tok in mod_low for tok in ("lfi", "path_traversal", "file_read")):
            poisons.append(PoisonEntry(
                capability="file_read",
                value="confirmed",
                source_module=module_path,
                confidence=0.9,
                metadata={"signal": "lfi_vulnerable"},
            ))
        if any(tok in mod_low for tok in ("rce", "cve_", "command_inj", "code_injection")):
            poisons.append(PoisonEntry(
                capability="rce",
                value="confirmed",
                source_module=module_path,
                confidence=0.92,
            ))
        if "upload" in mod_low:
            upload_val = ""
            if isinstance(details, dict):
                for key in ("upload_path", "upload_dir", "path"):
                    raw = details.get(key)
                    if isinstance(raw, str) and raw.strip():
                        upload_val = raw.strip()
                        break
            poisons.append(PoisonEntry(
                capability="upload_path",
                value=upload_val or "writable",
                source_module=module_path,
                confidence=0.85,
            ))

    auth_ctx_keys = ("post_login_snippet", "post_login_final_url", "authenticated_as", "session_cookie")
    if isinstance(details, dict) and any(details.get(k) for k in auth_ctx_keys):
        poisons.append(PoisonEntry(
            capability="authenticated_session",
            value="active",
            source_module=module_path,
            confidence=0.95,
        ))
        cookie = details.get("session_cookie") or details.get("cookie")
        if isinstance(cookie, str) and cookie.strip():
            poisons.append(PoisonEntry(
                capability="session_cookie",
                value=cookie.strip()[:512],
                source_module=module_path,
                confidence=0.93,
            ))

    if "sql" in mod_low and vulnerable:
        poisons.append(PoisonEntry(
            capability="db_access",
            value="confirmed",
            source_module=module_path,
            confidence=0.88,
        ))

    if any(x in blob.lower() for x in ("shell", "meterpreter", "reverse tcp")):
        poisons.append(PoisonEntry(
            capability="shell",
            value="obtained",
            source_module=module_path,
            confidence=0.97,
        ))

    return poisons


def extract_poisons_from_result(
    module_path: str,
    result: Mapping[str, Any],
    agent_meta: Optional[Mapping[str, Any]] = None,
    *,
    phase: str = "",
) -> List[PoisonEntry]:
    """Build poison entries from declared ``agent.chain`` metadata and heuristics."""
    poisons = _heuristic_poisons_from_result(module_path, result)
    chain = normalize_chain_block((agent_meta or {}).get("chain"))
    details = result.get("details") if isinstance(result, Mapping) else {}
    if not isinstance(details, dict):
        details = {}
    conf = 0.9 if bool(result.get("vulnerable")) else 0.65

    for spec in chain.get("produces_capabilities") or []:
        cap = str(spec.get("capability", "")).strip().lower()
        if not cap:
            continue
        from_detail = str(spec.get("from_detail", "") or "").strip()
        value = ""
        if from_detail:
            raw = details.get(from_detail)
            if isinstance(raw, str) and raw.strip():
                value = raw.strip()
        if not value:
            value = "confirmed" if bool(result.get("vulnerable")) else ""
        if value:
            entry = PoisonEntry(
                capability=cap,
                value=value,
                source_module=module_path,
                phase=phase,
                confidence=conf,
            )
            poisons.append(entry)

    for entry in poisons:
        if phase and not entry.phase:
            entry.phase = phase
    return poisons


def _result_blob(result: Mapping[str, Any]) -> str:
    if not isinstance(result, Mapping):
        return ""
    parts = [
        str(result.get("path", "") or ""),
        str(result.get("module", "") or ""),
        str(result.get("message", "") or ""),
        str(result.get("status", "") or ""),
        str(result.get("error", "") or ""),
    ]
    details = result.get("details")
    if isinstance(details, Mapping):
        for key in (
            "reason",
            "error",
            "indicator",
            "status_code",
            "evidence_snippet",
            "validation_status",
        ):
            value = details.get(key)
            if value is not None:
                parts.append(str(value)[:1000])
    return " ".join(parts)


def _observation_status(result: Mapping[str, Any]) -> str:
    if not isinstance(result, Mapping):
        return OBS_NO_SIGNAL
    blob = _result_blob(result)
    if bool(result.get("vulnerable")):
        return OBS_CONFIRMED
    status = str(result.get("status", "") or "").strip().lower()
    if _BLOCKED_RE.search(blob):
        return OBS_BLOCKED
    if status in {"error", "failed", "failure"} or bool(result.get("error")):
        return OBS_ERROR
    if _REFUTED_RE.search(blob):
        return OBS_REFUTED
    if _ERROR_RE.search(blob):
        return OBS_ERROR
    if result.get("vulnerable") is False:
        return OBS_NO_SIGNAL
    return OBS_NO_SIGNAL


def _status_confidence(status: str, result: Mapping[str, Any]) -> float:
    if status == OBS_CONFIRMED:
        return 0.92 if bool(result.get("vulnerable")) else 0.75
    if status == OBS_BLOCKED:
        return 0.82
    if status == OBS_ERROR:
        return 0.68
    if status == OBS_REFUTED:
        return 0.72
    return 0.45


def _chain_capability_hint(
    result: Mapping[str, Any],
    agent_meta: Optional[Mapping[str, Any]] = None,
) -> str:
    chain = normalize_chain_block((agent_meta or {}).get("chain"))
    produced = [
        str(row.get("capability", "")).strip().lower()
        for row in chain.get("produces_capabilities") or []
        if isinstance(row, Mapping) and str(row.get("capability", "")).strip()
    ]
    consumed = [
        str(cap).strip().lower()
        for cap in chain.get("consumes_capabilities") or []
        if str(cap).strip()
    ]
    if bool(result.get("vulnerable")) and produced:
        return produced[0]
    if consumed:
        return consumed[0]
    if produced:
        return produced[0]

    path = str(result.get("path", "") or "").lower()
    if "sql" in path or "sqli" in path:
        return "db_access"
    if "lfi" in path or "traversal" in path:
        return "file_read"
    if "ssrf" in path:
        return "ssrf_primitive"
    if "login" in path or "auth" in path:
        return "authenticated_session"
    if "smb" in path:
        return "smb_access"
    if "mysql" in path:
        return "mysql_access"
    return ""


def _observation_value(result: Mapping[str, Any], capability: str) -> str:
    details = result.get("details") if isinstance(result, Mapping) else {}
    if not isinstance(details, Mapping):
        details = {}
    preferred_keys = [
        "param",
        "parameter",
        "path",
        "target_path",
        "request_url",
        "url",
        "login_path",
        "status_code",
        "indicator",
    ]
    if capability == "file_read":
        preferred_keys = ["lfi_path", "target_path", "payload", "path"] + preferred_keys
    elif capability == "ssrf_primitive":
        preferred_keys = ["ssrf_param", "param", "payload"] + preferred_keys
    elif capability == "authenticated_session":
        preferred_keys = ["login_path", "post_login_final_path", "authenticated_as"] + preferred_keys
    elif capability.endswith("_access"):
        preferred_keys = ["target", "host", "port", "service"] + preferred_keys
    for key in preferred_keys:
        value = details.get(key)
        if isinstance(value, (str, int, float)) and str(value).strip():
            return redact_text(value, 180)
    return ""


def _proof_summary(result: Mapping[str, Any], status: str) -> str:
    details = result.get("details") if isinstance(result, Mapping) else {}
    parts: List[str] = []
    msg = str(result.get("message", "") or "").strip()
    if msg:
        parts.append(msg)
    if isinstance(details, Mapping):
        for key in (
            "reason",
            "error",
            "indicator",
            "status_code",
            "evidence_snippet",
            "validation_status",
            "rce_confirmed",
            "cloud_provider",
        ):
            value = details.get(key)
            if value is not None and str(value).strip():
                parts.append(f"{key}={value}")
    if not parts:
        parts.append(status)
    return redact_text(" | ".join(parts), MAX_PROOF_LEN)


def extract_observation_from_result(
    module_path: str,
    result: Mapping[str, Any],
    agent_meta: Optional[Mapping[str, Any]] = None,
    *,
    phase: str = "",
) -> ChainObservation:
    """Build a compact positive/negative observation from an executed module result."""
    row = enrich_result_details_for_chain(result) if isinstance(result, Mapping) else {}
    path = str(module_path or row.get("path", "") or "").strip()
    status = _observation_status(row)
    capability = _chain_capability_hint(row, agent_meta)
    value = _observation_value(row, capability)
    proof = _proof_summary(row, status)
    return ChainObservation(
        module_path=path,
        status=status,
        capability=capability,
        value=value,
        phase=phase,
        confidence=_status_confidence(status, row),
        proof_summary=proof,
        reason=proof,
        target=str(row.get("target") or row.get("host") or ""),
        metadata={
            "severity": str(row.get("severity", "") or ""),
            "result_status": str(row.get("status", "") or ""),
            "vulnerable": bool(row.get("vulnerable")),
        },
    )


def record_chain_observations_from_results(
    kb: MutableMapping[str, Any],
    results: Iterable[Mapping[str, Any]],
    *,
    phase: str = "",
    module_agent_meta: Optional[Mapping[str, Mapping[str, Any]]] = None,
) -> int:
    """Record observations for executed modules; returns number of new rows."""
    if not isinstance(kb, MutableMapping):
        return 0
    before = len(get_memory(kb).get("observations") or [])
    meta_map = module_agent_meta or {}
    observations: List[ChainObservation] = []
    for result in results or []:
        if not isinstance(result, Mapping):
            continue
        path = str(result.get("path", "") or "").strip()
        agent = meta_map.get(path) or meta_map.get(path.lower()) or {}
        observations.append(
            extract_observation_from_result(path, result, agent, phase=phase)
        )
    apply_observations_to_kb(kb, observations)
    after = len(get_memory(kb).get("observations") or [])
    return max(0, after - before)


def poison_kb_from_results(
    kb: MutableMapping[str, Any],
    results: Iterable[Mapping[str, Any]],
    *,
    phase: str = "",
    module_agent_meta: Optional[Mapping[str, Mapping[str, Any]]] = None,
) -> int:
    """
    Extract and apply poisons from a batch of module results.

    Returns the number of new poison entries merged.
    """
    if not isinstance(kb, MutableMapping):
        return 0
    before = len(get_memory(kb).get("entries") or [])
    meta_map = module_agent_meta or {}
    for result in results or []:
        if not isinstance(result, Mapping):
            continue
        result = enrich_result_details_for_chain(result)
        path = str(result.get("path", "") or "").strip()
        agent = meta_map.get(path) or meta_map.get(path.lower()) or {}
        poisons = extract_poisons_from_result(path, result, agent, phase=phase)
        apply_poisons_to_kb(kb, poisons)
        apply_observations_to_kb(
            kb,
            [extract_observation_from_result(path, result, agent, phase=phase)],
        )
    after = len(get_memory(kb).get("entries") or [])
    return max(0, after - before)


def build_chain_option_overrides(
    modules: Iterable[Mapping[str, Any]],
    kb: Mapping[str, Any],
) -> Dict[str, Dict[str, Any]]:
    """
    Map poisoned capabilities to module option names via ``agent.chain.option_bindings``.
    """
    if not isinstance(kb, Mapping):
        return {}
    overrides: Dict[str, Dict[str, Any]] = {}
    for module in modules or []:
        if not isinstance(module, Mapping):
            continue
        path = str(module.get("path", "") or "").strip()
        if not path:
            continue
        agent = module.get("agent")
        if not isinstance(agent, dict):
            continue
        chain = normalize_chain_block(agent.get("chain"))
        bindings = chain.get("option_bindings") or {}
        if not bindings:
            continue
        mod_overrides: Dict[str, Any] = {}
        for opt_name, capability in bindings.items():
            value = best_capability_value(kb, str(capability))
            if value and value != "confirmed":
                mod_overrides[str(opt_name)] = value
        if mod_overrides:
            overrides[path] = mod_overrides
    return overrides


def chain_readiness_bonus(module: Mapping[str, Any], kb: Mapping[str, Any]) -> float:
    """
    Score boost when poisoned memory satisfies declared chain prerequisites.

    Typical range ``0.0 .. 1.6``.
    """
    agent = module.get("agent") if isinstance(module, Mapping) else None
    if not isinstance(agent, dict):
        return 0.0
    chain = normalize_chain_block(agent.get("chain"))
    consumes = chain.get("consumes_capabilities") or []
    if not consumes:
        return 0.0
    present = capabilities_present(kb if isinstance(kb, Mapping) else {})
    matched = sum(1 for cap in consumes if cap in present)
    if matched == 0:
        return 0.0
    ratio = matched / max(1, len(consumes))
    return round(0.35 + 1.25 * ratio, 3)


def chain_observation_penalty(module: Mapping[str, Any], kb: Mapping[str, Any]) -> float:
    """
    Soft penalty from negative observations.

    Exact repeated blockers/errors matter most; capability-level refutations add
    a small drag so the planner explores alternatives before retrying the same
    branch.
    """
    if not isinstance(kb, Mapping) or not isinstance(module, Mapping):
        return 0.0
    path = str(module.get("path", "") or "").strip().lower()
    if not path:
        return 0.0
    base = path.rsplit("/", 1)[-1]
    agent = module.get("agent")
    chain = normalize_chain_block(agent.get("chain") if isinstance(agent, Mapping) else None)
    caps = {
        str(cap).strip().lower()
        for cap in chain.get("consumes_capabilities") or []
        if str(cap).strip()
    }
    caps.update(
        str(row.get("capability", "")).strip().lower()
        for row in chain.get("produces_capabilities") or []
        if isinstance(row, Mapping) and str(row.get("capability", "")).strip()
    )
    weights = {
        OBS_BLOCKED: 1.35,
        OBS_ERROR: 0.85,
        OBS_REFUTED: 0.65,
        OBS_NO_SIGNAL: 0.28,
    }
    penalty = 0.0
    for row in get_observations(kb, statuses=NEGATIVE_OBSERVATION_STATUSES)[-96:]:
        obs_path = str(row.get("module_path", "") or "").strip().lower()
        if not obs_path:
            continue
        obs_base = obs_path.rsplit("/", 1)[-1]
        status = str(row.get("status", "") or "").strip().lower()
        weight = weights.get(status, 0.0)
        if weight <= 0:
            continue
        try:
            conf = max(0.2, min(1.0, float(row.get("confidence", 0.5) or 0.5)))
        except (TypeError, ValueError):
            conf = 0.5
        try:
            count = max(1, min(4, int(row.get("count", 1) or 1)))
        except (TypeError, ValueError):
            count = 1
        repeat = 1.0 + (count - 1) * 0.22
        if path == obs_path:
            penalty += weight * conf * repeat
            continue
        if base and base == obs_base:
            penalty += weight * conf * 0.72
            continue
        obs_cap = str(row.get("capability", "") or "").strip().lower()
        if obs_cap and obs_cap in caps and status in {OBS_REFUTED, OBS_BLOCKED}:
            penalty += weight * conf * 0.35
    return round(min(2.2, penalty), 3)


def suggest_chain_module_paths(kb: Mapping[str, Any]) -> Set[str]:
    """Collect ``suggested_followups`` from modules whose consumes are satisfied."""
    if not isinstance(kb, Mapping):
        return set()
    catalog = kb.get("module_capability_catalog") or {}
    modules = catalog.get("modules") or catalog.get("all_modules") or []
    if not isinstance(modules, list):
        modules = []
    present = capabilities_present(kb)
    wanted: Set[str] = set()
    for mod in modules:
        if not isinstance(mod, dict):
            continue
        agent = mod.get("agent")
        if not isinstance(agent, dict):
            continue
        chain = normalize_chain_block(agent.get("chain"))
        consumes = chain.get("consumes_capabilities") or []
        if consumes and not all(cap in present for cap in consumes):
            continue
        for path in chain.get("suggested_followups") or []:
            if path:
                wanted.add(str(path).strip())
    try:
        from interfaces.command_system.builtin.agent.ot_policy import suggest_ot_active_handoff
        for path in suggest_ot_active_handoff(dict(kb)):
            wanted.add(str(path).strip())
    except Exception:
        pass
    return wanted


def export_chain_summary(kb: Mapping[str, Any]) -> Dict[str, Any]:
    """Compact summary for reports and operator visibility."""
    memory = get_memory(kb if isinstance(kb, Mapping) else {})
    entries = memory.get("entries") or []
    observations = memory.get("observations") or []
    by_cap: Dict[str, int] = {}
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        cap = str(entry.get("capability", "")).lower()
        by_cap[cap] = by_cap.get(cap, 0) + 1
    by_status: Dict[str, int] = {}
    blocked_modules: List[str] = []
    refuted_capabilities: Set[str] = set()
    for row in observations:
        if not isinstance(row, dict):
            continue
        status = str(row.get("status", "") or OBS_NO_SIGNAL).lower()
        by_status[status] = by_status.get(status, 0) + 1
        if status == OBS_BLOCKED:
            path = str(row.get("module_path", "") or "").strip()
            if path and path not in blocked_modules:
                blocked_modules.append(path)
        if status == OBS_REFUTED:
            cap = str(row.get("capability", "") or "").strip().lower()
            if cap:
                refuted_capabilities.add(cap)
    recent_observations = []
    for row in observations[-8:]:
        if not isinstance(row, dict):
            continue
        recent_observations.append({
            "module_path": str(row.get("module_path", "") or ""),
            "status": str(row.get("status", "") or ""),
            "capability": str(row.get("capability", "") or ""),
            "confidence": float(row.get("confidence", 0.0) or 0.0),
            "count": int(row.get("count", 1) or 1),
            "reason": str(row.get("reason", "") or "")[:180],
        })
    return {
        "entries": len(entries),
        "observations": len(observations),
        "chain_steps": len(memory.get("chain_ids") or []),
        "capabilities": sorted(by_cap.keys()),
        "capability_counts": by_cap,
        "observation_counts": by_status,
        "blocked_modules": blocked_modules[:8],
        "refuted_capabilities": sorted(refuted_capabilities),
        "recent_observations": recent_observations,
    }
