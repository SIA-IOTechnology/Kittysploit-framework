#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Bridge persistent credential vault into agent knowledge and planning."""

from __future__ import annotations

import os
from typing import Any, Dict, Mapping, MutableMapping, Optional

from interfaces.command_system.builtin.agent.redaction import sanitize_nested

AUTO_CAPTURE_ENV = "KITTYSPLOIT_VAULT_AUTO_CAPTURE"


def resolve_agent_framework(state: Any = None, framework: Any = None) -> Any:
    if framework is not None:
        return framework
    if state is not None:
        bound = getattr(state, "framework", None)
        if bound is not None:
            return bound
    return None


def vault_auto_capture_enabled() -> bool:
    raw = os.environ.get(AUTO_CAPTURE_ENV, "").strip().lower()
    return raw in {"1", "true", "yes", "on"}


def capture_discovered_credentials(
    kb: Mapping[str, Any],
    *,
    state: Any = None,
    framework: Any = None,
) -> int:
    """Persist newly discovered run credentials into the encrypted vault (optional)."""
    if not vault_auto_capture_enabled():
        return 0
    fw = resolve_agent_framework(state, framework)
    if fw is None or not getattr(fw, "is_encryption_loaded", lambda: False)():
        return 0
    if not isinstance(kb, dict):
        return 0
    from interfaces.command_system.builtin.agent.credential_vault import get_credential_vault
    from core.vault.persistent_store import get_persistent_vault

    vault = get_credential_vault(state=state, kb=kb, framework=fw)
    store = get_persistent_vault(fw)
    imported = store.import_from_kb(kb, vault_resolver=vault)
    return len(imported)


def sync_agent_vault_context(
    kb: MutableMapping[str, Any],
    *,
    state: Any = None,
    framework: Any = None,
    resync_lateral: bool = True,
) -> Dict[str, Any]:
    """Expose persistent vault metadata to the agent KB and lateral planner."""
    if not isinstance(kb, MutableMapping):
        return {}
    fw = resolve_agent_framework(state, framework)
    snapshot: Dict[str, Any] = {
        "schema_version": "1.0",
        "entry_count": 0,
        "entries": [],
        "available": False,
    }
    if fw is None or not getattr(fw, "is_encryption_loaded", lambda: False)():
        kb["persistent_vault"] = snapshot
        return snapshot

    try:
        from core.vault.persistent_store import get_persistent_vault

        records = get_persistent_vault(fw).list_records()
    except RuntimeError:
        kb["persistent_vault"] = snapshot
        return snapshot

    entries = [record.to_public_dict() for record in records[:12]]
    snapshot = sanitize_nested({
        "schema_version": "1.0",
        "entry_count": len(records),
        "entries": entries,
        "available": bool(entries),
    })
    kb["persistent_vault"] = snapshot

    existing_rows = []
    seen_handles = set()
    for row in kb.get("credential_store") or []:
        if not isinstance(row, dict):
            continue
        clone = dict(row)
        handle = str(clone.get("password") or clone.get("authenticated_password") or "").strip()
        if handle:
            seen_handles.add(handle)
        existing_rows.append(clone)

    for record in records:
        if record.handle in seen_handles:
            continue
        existing_rows.append({
            "username": record.username,
            "password": record.handle,
            "source_module": record.origin,
            "source_host": record.source_host,
            "protocol_hint": record.protocol_hint,
            "origin": "persistent_vault",
            "credential_id": record.credential_id,
            "scope_hosts": list(record.scope_hosts),
            "scope_ports": list(record.scope_ports),
            "expires_at": record.expires_at,
        })
        seen_handles.add(record.handle)

    kb["credential_store"] = existing_rows[:8]

    if resync_lateral:
        from interfaces.command_system.builtin.agent.scope_lateral import sync_scope_lateral

        sync_scope_lateral(kb, state=state)

    return snapshot


def bind_agent_runtime(framework: Any, state: Any) -> None:
    """Attach live framework reference and refresh vault context on agent state."""
    if state is None:
        return
    state.framework = framework
    kb = getattr(state, "knowledge_base", None)
    if isinstance(kb, dict):
        from interfaces.command_system.builtin.agent.credential_vault import get_credential_vault

        get_credential_vault(state=state, kb=kb, framework=framework)
        sync_agent_vault_context(kb, state=state, framework=framework)
