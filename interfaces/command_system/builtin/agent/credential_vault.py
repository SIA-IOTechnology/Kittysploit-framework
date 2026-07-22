#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""In-memory credential vault with opaque handles and executor-only resolution."""

from __future__ import annotations

import hashlib
import os
import time
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, Mapping, MutableMapping, Optional, Sequence

from interfaces.command_system.builtin.agent.redaction import is_sensitive_key, sanitize_nested

VAULT_PREFIX = "vault:"
DEFAULT_VAULT_TTL_SECONDS = 3600.0

_RUN_VAULTS: Dict[str, "CredentialVault"] = {}

SENSITIVE_AUTH_FIELDS = (
    "password",
    "authenticated_password",
    "cookie_header",
    "session_cookie",
    "token",
    "api_key",
    "apikey",
    "authorization",
)

SENSITIVE_OPTION_KEYS = frozenset({
    "password",
    "pass",
    "passwd",
    "token",
    "api_key",
    "apikey",
    "cookie",
    "cookie_header",
    "session_cookie",
    "credentials",
    "private_key",
})


@dataclass
class VaultEntry:
    handle: str
    kind: str
    value: str
    created_at: float = field(default_factory=time.time)
    expires_at: float = 0.0
    source: str = ""

    def to_index_dict(self) -> Dict[str, Any]:
        return {
            "handle": self.handle,
            "kind": self.kind,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "source": self.source,
        }


def vault_ttl_seconds() -> float:
    raw = os.environ.get("KITTYSPLOIT_AGENT_VAULT_TTL", "").strip()
    if raw:
        try:
            return max(60.0, float(raw))
        except ValueError:
            pass
    return DEFAULT_VAULT_TTL_SECONDS


def is_vault_handle(value: Any) -> bool:
    return isinstance(value, str) and value.startswith(VAULT_PREFIX) and len(value) > len(VAULT_PREFIX) + 3


def _value_fingerprint(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()


class CredentialVault:
    """Run-scoped secret store. Values never belong in KB, prompts, or checkpoints."""

    def __init__(self, *, run_id: str = "", ttl_seconds: Optional[float] = None) -> None:
        self.run_id = str(run_id or "")
        self.ttl_seconds = float(ttl_seconds if ttl_seconds is not None else vault_ttl_seconds())
        self._entries: Dict[str, VaultEntry] = {}
        self._fingerprints: Dict[str, str] = {}

    def store(self, value: Any, *, kind: str = "secret", source: str = "") -> str:
        text = str(value or "").strip()
        if not text:
            return ""
        if is_vault_handle(text):
            return text
        fp = _value_fingerprint(text)
        existing = self._fingerprints.get(fp)
        if existing and existing in self._entries and not self._is_expired(self._entries[existing]):
            return existing
        digest = hashlib.sha256(f"{self.run_id}:{kind}:{fp}".encode("utf-8")).hexdigest()[:12]
        handle = f"{VAULT_PREFIX}{kind}:{digest}"
        now = time.time()
        self._entries[handle] = VaultEntry(
            handle=handle,
            kind=kind,
            value=text,
            created_at=now,
            expires_at=now + self.ttl_seconds,
            source=str(source or "")[:160],
        )
        self._fingerprints[fp] = handle
        return handle

    @staticmethod
    def _is_expired(entry: VaultEntry) -> bool:
        return bool(entry.expires_at and entry.expires_at < time.time())

    def resolve(self, value: Any) -> Any:
        if not is_vault_handle(value):
            return value
        entry = self._entries.get(str(value))
        if entry is None or self._is_expired(entry):
            return ""
        return entry.value

    def resolve_tree(self, value: Any) -> Any:
        if is_vault_handle(value):
            return self.resolve(value)
        if isinstance(value, dict):
            return {str(key): self.resolve_tree(item) for key, item in value.items()}
        if isinstance(value, list):
            return [self.resolve_tree(item) for item in value]
        if isinstance(value, tuple):
            return tuple(self.resolve_tree(item) for item in value)
        return value

    def revoke(self, handle: str) -> bool:
        token = str(handle or "").strip()
        if token not in self._entries:
            return False
        entry = self._entries.pop(token)
        fp = _value_fingerprint(entry.value)
        if self._fingerprints.get(fp) == token:
            self._fingerprints.pop(fp, None)
        return True

    def purge_expired(self) -> int:
        removed = 0
        for handle in list(self._entries.keys()):
            if self._is_expired(self._entries[handle]):
                self.revoke(handle)
                removed += 1
        return removed

    def export_index(self) -> Dict[str, Any]:
        self.purge_expired()
        return sanitize_nested({
            "schema_version": "1.0",
            "run_id": self.run_id,
            "ttl_seconds": self.ttl_seconds,
            "handles": [entry.to_index_dict() for entry in self._entries.values()],
        })


def get_credential_vault(state: Any = None, kb: Any = None) -> CredentialVault:
    if state is not None:
        vault = getattr(state, "credential_vault", None)
        if isinstance(vault, CredentialVault):
            return vault
    run_id = ""
    if state is not None:
        run_id = str(getattr(state, "run_id", "") or "")
    if not run_id and isinstance(kb, dict):
        run_id = str(kb.get("_vault_run_id") or kb.get("run_id") or "")
    if not run_id:
        run_id = "anonymous"
    vault = _RUN_VAULTS.get(run_id)
    if vault is None:
        vault = CredentialVault(run_id=run_id)
        _RUN_VAULTS[run_id] = vault
    if state is not None:
        state.credential_vault = vault
    if isinstance(kb, dict):
        kb["_vault_run_id"] = run_id
    return vault


def sync_vault_index_to_kb(kb: MutableMapping[str, Any], vault: CredentialVault) -> None:
    if not isinstance(kb, MutableMapping):
        return
    kb["credential_vault_index"] = vault.export_index()


def vault_sensitive_fields(
    payload: MutableMapping[str, Any],
    vault: CredentialVault,
    *,
    source: str = "",
) -> None:
    if not isinstance(payload, MutableMapping):
        return
    for key in list(payload.keys()):
        value = payload.get(key)
        low = str(key).lower()
        if low in SENSITIVE_AUTH_FIELDS or is_sensitive_key(key):
            if isinstance(value, dict):
                nested: Dict[str, Any] = {}
                for sub_key, sub_val in value.items():
                    if is_sensitive_key(sub_key) or low == "cookies":
                        nested[str(sub_key)] = vault.store(sub_val, kind="cookie", source=source or low)
                    else:
                        nested[str(sub_key)] = sub_val
                payload[key] = nested
            elif isinstance(value, str) and value.strip():
                kind = "password" if "pass" in low else "secret"
                payload[key] = vault.store(value, kind=kind, source=source or low)
        elif isinstance(value, dict):
            vault_sensitive_fields(value, vault, source=source or low)


def sanitize_credential_store_for_export(kb: Mapping[str, Any]) -> Dict[str, Any]:
    """Return a planner-safe view of credential metadata without resolvable secrets."""
    if not isinstance(kb, dict):
        return {}
    rows = []
    for row in kb.get("credential_store") or []:
        if not isinstance(row, dict):
            continue
        safe = sanitize_nested(dict(row))
        for key, value in list(safe.items()):
            if is_sensitive_key(key) and value and value != "[redacted]":
                if not is_vault_handle(value):
                    safe[key] = "[redacted]"
        rows.append(safe)
    active = kb.get("active_auth_context")
    active_safe = dict(active) if isinstance(active, dict) else {}
    for key, value in list(active_safe.items()):
        if is_sensitive_key(key) and value and not is_vault_handle(str(value)):
            active_safe[key] = "[redacted]"
    return {
        "credential_store": rows[:6],
        "active_auth_context": active_safe,
        "credential_vault_index": sanitize_nested(kb.get("credential_vault_index") or {}),
    }


def resolve_option_mapping(options: Mapping[str, Any], vault: CredentialVault) -> Dict[str, Any]:
    resolved: Dict[str, Any] = {}
    for key, value in (options or {}).items():
        if str(key).lower() in SENSITIVE_OPTION_KEYS or is_sensitive_key(key):
            resolved[key] = vault.resolve_tree(value)
        elif is_vault_handle(value):
            resolved[key] = vault.resolve(value)
        else:
            resolved[key] = value
    return resolved


def apply_resolved_options(module_instance: Any, options: Mapping[str, Any], vault: CredentialVault) -> None:
    resolved = resolve_option_mapping(options, vault)
    setter = getattr(module_instance, "set_option", None)
    if not callable(setter):
        return
    for key, value in resolved.items():
        try:
            setter(key, value)
        except Exception:
            continue


def resolve_module_instance_options(module_instance: Any, state: Any) -> None:
    """Resolve vault handles already set on a module instance (executor boundary)."""
    vault = get_credential_vault(state)
    for key in SENSITIVE_OPTION_KEYS:
        if not hasattr(module_instance, key):
            continue
        try:
            current = getattr(module_instance, key)
        except Exception:
            continue
        if is_vault_handle(current):
            try:
                module_instance.set_option(key, vault.resolve(current))
            except Exception:
                continue


def scrub_plaintext_secrets_in_kb(kb: MutableMapping[str, Any], vault: CredentialVault) -> None:
    """Migrate legacy plaintext credential_store rows to vault handles."""
    if not isinstance(kb, MutableMapping):
        return
    store = kb.get("credential_store")
    if isinstance(store, list):
        for row in store:
            if isinstance(row, dict):
                vault_sensitive_fields(row, vault, source="credential_store")
    active = kb.get("active_auth_context")
    if isinstance(active, dict):
        vault_sensitive_fields(active, vault, source="active_auth_context")
    sync_vault_index_to_kb(kb, vault)
