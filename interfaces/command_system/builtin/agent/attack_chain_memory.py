#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Stateful attack chains via memory poisoning.

Each successful module step can **poison** the campaign knowledge base with
structured capabilities (session cookies, log paths, upload dirs, etc.).
Downstream modules declare ``agent.chain.consumes_capabilities`` and
``option_bindings`` so the planner can chain stateful follow-ups and pre-fill
module options from poisoned memory — without storing raw secrets in the poison
store when redaction applies.

Persisted on the in-memory KB under ``attack_chain_memory``::

    {
      "version": 1,
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
      "chain_ids": ["a1b2", "c3d4"]
    }
"""

from __future__ import annotations

import hashlib
import logging
import re
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, Iterable, List, Mapping, MutableMapping, Optional, Set

from .chain_meta import normalize_chain_block

logger = logging.getLogger(__name__)

MEMORY_KEY = "attack_chain_memory"
MEMORY_VERSION = 1
MAX_ENTRIES = 96
MAX_CHAIN_IDS = 48
MAX_VALUE_LEN = 4096

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
    "rce",
    "shell",
    "root",
    "admin_access",
    "cloud_credentials",
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
    "csrf_token": "csrf_token",
    "database": "db_access",
    "db_name": "db_access",
}

_LOG_PATH_RE = re.compile(
    r"(/var/log/[^\s\"']+|/proc/self/[^\s\"']+|/etc/passwd)",
    re.IGNORECASE,
)


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


def _empty_memory() -> Dict[str, Any]:
    return {"version": MEMORY_VERSION, "entries": [], "chain_ids": []}


def get_memory(kb: Mapping[str, Any]) -> Dict[str, Any]:
    raw = kb.get(MEMORY_KEY) if isinstance(kb, Mapping) else None
    if not isinstance(raw, dict):
        return _empty_memory()
    entries = raw.get("entries")
    chain_ids = raw.get("chain_ids")
    return {
        "version": int(raw.get("version", MEMORY_VERSION) or MEMORY_VERSION),
        "entries": list(entries) if isinstance(entries, list) else [],
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
        "chain_ids": chain_ids,
    }
    sync_unlocked_capabilities(kb)


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
        path = str(result.get("path", "") or "").strip()
        agent = meta_map.get(path) or meta_map.get(path.lower()) or {}
        poisons = extract_poisons_from_result(path, result, agent, phase=phase)
        apply_poisons_to_kb(kb, poisons)
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
    return wanted


def export_chain_summary(kb: Mapping[str, Any]) -> Dict[str, Any]:
    """Compact summary for reports and operator visibility."""
    memory = get_memory(kb if isinstance(kb, Mapping) else {})
    entries = memory.get("entries") or []
    by_cap: Dict[str, int] = {}
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        cap = str(entry.get("capability", "")).lower()
        by_cap[cap] = by_cap.get(cap, 0) + 1
    return {
        "entries": len(entries),
        "chain_steps": len(memory.get("chain_ids") or []),
        "capabilities": sorted(by_cap.keys()),
        "capability_counts": by_cap,
    }
