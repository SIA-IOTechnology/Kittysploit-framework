#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Workspace-scoped encrypted credential vault stored in the workspace database."""

from __future__ import annotations

import hashlib
import json
import os
import re
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

from core.models.models import VaultCredentialEntry, Workspace
from interfaces.command_system.builtin.agent.credential_vault import VAULT_PREFIX, is_vault_handle
from interfaces.command_system.builtin.agent.redaction import sanitize_nested

PERSIST_PREFIX = f"{VAULT_PREFIX}persist:"
DEFAULT_TTL_SECONDS = 86400.0 * 30
_DB_SESSION_KEY = "default"


def _safe_component(value: str, fallback: str = "default") -> str:
    clean = re.sub(r"[^a-zA-Z0-9_.-]+", "_", str(value or "")).strip("._")
    return clean[:120] or fallback


def _now() -> float:
    return time.time()


def _parse_ttl(raw: str) -> float:
    text = str(raw or "").strip().lower()
    if not text:
        return DEFAULT_TTL_SECONDS
    if text.endswith("h"):
        return max(3600.0, float(text[:-1]) * 3600.0)
    if text.endswith("d"):
        return max(3600.0, float(text[:-1]) * 86400.0)
    if text.endswith("m"):
        return max(60.0, float(text[:-1]) * 60.0)
    return max(3600.0, float(text))


def _dt_to_ts(value: Any) -> float:
    if value is None:
        return 0.0
    if isinstance(value, datetime):
        try:
            if value.tzinfo is None:
                return value.replace(tzinfo=timezone.utc).timestamp()
            return value.timestamp()
        except (TypeError, ValueError, OSError):
            return 0.0
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def _ts_to_dt(value: float) -> Optional[datetime]:
    if not value:
        return None
    try:
        return datetime.utcfromtimestamp(float(value))
    except (TypeError, ValueError, OSError):
        return None


@dataclass
class PersistentCredentialRecord:
    credential_id: str
    handle: str
    kind: str = "password"
    username: str = ""
    origin: str = ""
    source_host: str = ""
    scope_hosts: List[str] = field(default_factory=list)
    scope_ports: List[int] = field(default_factory=list)
    protocol_hint: str = ""
    created_at: float = field(default_factory=_now)
    expires_at: float = 0.0
    last_used_at: float = 0.0
    notes: str = ""

    def is_expired(self) -> bool:
        return bool(self.expires_at and self.expires_at < _now())

    def to_public_dict(self) -> Dict[str, Any]:
        return sanitize_nested({
            "credential_id": self.credential_id,
            "handle": self.handle,
            "kind": self.kind,
            "username": self.username,
            "origin": self.origin,
            "source_host": self.source_host,
            "scope_hosts": self.scope_hosts,
            "scope_ports": self.scope_ports,
            "protocol_hint": self.protocol_hint,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "last_used_at": self.last_used_at,
            "expired": self.is_expired(),
            "notes": self.notes,
        })

    @classmethod
    def from_row(cls, row: VaultCredentialEntry) -> "PersistentCredentialRecord":
        scope_hosts = row.scope_hosts if isinstance(row.scope_hosts, list) else []
        scope_ports: List[int] = []
        for item in row.scope_ports or []:
            try:
                scope_ports.append(int(item))
            except (TypeError, ValueError):
                continue
        return cls(
            credential_id=str(row.credential_id or ""),
            handle=str(row.handle or ""),
            kind=str(row.kind or "password"),
            username=str(row.username or ""),
            origin=str(row.origin or ""),
            source_host=str(row.source_host or ""),
            scope_hosts=[str(item) for item in scope_hosts if str(item).strip()],
            scope_ports=scope_ports,
            protocol_hint=str(row.protocol_hint or ""),
            created_at=_dt_to_ts(row.created_at),
            expires_at=_dt_to_ts(row.expires_at),
            last_used_at=_dt_to_ts(row.last_used_at),
            notes=str(row.notes or ""),
        )


class PersistentCredentialStore:
    """Encrypted credential store scoped to one workspace (SQLite + master key)."""

    def __init__(self, framework: Any, *, workspace: str = "") -> None:
        self.framework = framework
        self.workspace = _safe_component(
            workspace or getattr(framework, "get_current_workspace_name", lambda: "default")(),
        )
        self._legacy_store_path = (
            Path(os.environ.get("KITTYSPLOIT_VAULT_HOME", "~/.kittysploit/vault")).expanduser()
            / self.workspace
            / "credentials.json"
        )
        self._legacy_migrated = False

    @property
    def storage_backend(self) -> str:
        db_manager = getattr(self.framework, "db_manager", None)
        if db_manager is None:
            return "database"
        try:
            return db_manager._resolve_db_path()
        except Exception:
            return "database"

    def _require_encryption(self) -> None:
        manager = getattr(self.framework, "encryption_manager", None)
        if manager is None or not getattr(manager, "_is_initialized", False):
            raise RuntimeError("Encryption is not unlocked. Start KittySploit and unlock the master password first.")

    def _db_manager(self):
        db_manager = getattr(self.framework, "db_manager", None)
        if db_manager is None:
            raise RuntimeError("Database manager is not available")
        return db_manager

    def _ensure_schema(self) -> None:
        db_manager = self._db_manager()
        if _DB_SESSION_KEY not in db_manager.engines:
            db_manager.init_workspace_db(_DB_SESSION_KEY)
        engine = db_manager.engines.get(_DB_SESSION_KEY)
        if engine is not None:
            VaultCredentialEntry.__table__.create(engine, checkfirst=True)
        if self.encryption_manager_ready():
            db_manager.set_encryption_manager(self.framework.encryption_manager)

    def encryption_manager_ready(self) -> bool:
        manager = getattr(self.framework, "encryption_manager", None)
        return bool(manager and getattr(manager, "_is_initialized", False))

    def _resolve_workspace_id(self, session) -> int:
        workspace_manager = getattr(self.framework, "workspace_manager", None)
        if workspace_manager is not None:
            current = workspace_manager.get_current_workspace()
            if current is not None and str(current.name) == self.workspace:
                return int(current.id)
        row = session.query(Workspace).filter(Workspace.name == self.workspace).first()
        if row is not None:
            return int(row.id)
        fallback = session.query(Workspace).filter(Workspace.is_active.is_(True)).first()
        if fallback is not None:
            return int(fallback.id)
        created = Workspace(
            name=self.workspace,
            description=f"Workspace {self.workspace}",
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow(),
            is_active=True,
        )
        session.add(created)
        session.flush()
        return int(created.id)

    def _migrate_legacy_json_if_present(self, session, workspace_id: int) -> None:
        if self._legacy_migrated:
            return
        self._legacy_migrated = True
        legacy_path = self._legacy_store_path
        if not legacy_path.is_file():
            return
        try:
            payload = json.loads(legacy_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return
        if not isinstance(payload, dict):
            return
        encryption = getattr(self.framework, "encryption_manager", None)
        imported = 0
        for row in payload.get("credentials") or []:
            if not isinstance(row, dict):
                continue
            credential_id = str(row.get("credential_id") or "").strip()
            handle = str(row.get("handle") or "").strip()
            if not credential_id or not handle:
                continue
            exists = session.query(VaultCredentialEntry).filter_by(
                workspace_id=workspace_id,
                credential_id=credential_id,
            ).first()
            if exists is not None:
                continue
            secret = ""
            encrypted = str(row.get("secret_encrypted") or "").strip()
            if encrypted and encryption is not None and getattr(encryption, "_is_initialized", False):
                try:
                    secret = str(encryption.decrypt_field(encrypted) or "")
                except Exception:
                    secret = ""
            if not secret:
                continue
            entry = VaultCredentialEntry(
                workspace_id=workspace_id,
                credential_id=credential_id,
                handle=handle,
                kind=str(row.get("kind") or "password"),
                username=str(row.get("username") or ""),
                secret=secret,
                origin=str(row.get("origin") or "legacy_import")[:255],
                source_host=str(row.get("source_host") or "")[:255],
                scope_hosts=[str(item) for item in (row.get("scope_hosts") or []) if str(item).strip()],
                scope_ports=[int(item) for item in (row.get("scope_ports") or []) if str(item).strip().isdigit()],
                protocol_hint=str(row.get("protocol_hint") or "")[:32],
                created_at=_ts_to_dt(float(row.get("created_at") or _now())) or datetime.utcnow(),
                expires_at=_ts_to_dt(float(row.get("expires_at") or 0.0)),
                last_used_at=_ts_to_dt(float(row.get("last_used_at") or 0.0)),
                notes=str(row.get("notes") or "")[:500],
            )
            session.add(entry)
            imported += 1
        if imported:
            session.flush()
            migrated = legacy_path.with_suffix(".json.migrated")
            try:
                legacy_path.replace(migrated)
            except OSError:
                pass

    def _query_entry(self, session, workspace_id: int, token: str) -> Optional[VaultCredentialEntry]:
        token = str(token or "").strip()
        if not token:
            return None
        row = session.query(VaultCredentialEntry).filter_by(
            workspace_id=workspace_id,
            credential_id=token,
        ).first()
        if row is not None:
            return row
        row = session.query(VaultCredentialEntry).filter_by(
            workspace_id=workspace_id,
            handle=token,
        ).first()
        if row is not None:
            return row
        digest_match = re.search(r":([a-f0-9]{12})$", token)
        if digest_match:
            suffix = digest_match.group(1)
            for candidate in session.query(VaultCredentialEntry).filter_by(workspace_id=workspace_id):
                if candidate.handle.endswith(suffix) or candidate.credential_id.endswith(suffix):
                    return candidate
        return None

    def list_records(self, *, include_expired: bool = False) -> List[PersistentCredentialRecord]:
        self._require_encryption()
        self._ensure_schema()
        db_manager = self._db_manager()
        rows: List[PersistentCredentialRecord] = []
        with db_manager.session_scope(_DB_SESSION_KEY) as session:
            workspace_id = self._resolve_workspace_id(session)
            self._migrate_legacy_json_if_present(session, workspace_id)
            query = session.query(VaultCredentialEntry).filter_by(workspace_id=workspace_id)
            for row in query.all():
                record = PersistentCredentialRecord.from_row(row)
                if not include_expired and record.is_expired():
                    continue
                rows.append(record)
        rows.sort(key=lambda item: (-item.created_at, item.username.lower()))
        return rows

    def get(self, token: str) -> Optional[PersistentCredentialRecord]:
        self._require_encryption()
        self._ensure_schema()
        db_manager = self._db_manager()
        with db_manager.session_scope(_DB_SESSION_KEY) as session:
            workspace_id = self._resolve_workspace_id(session)
            self._migrate_legacy_json_if_present(session, workspace_id)
            row = self._query_entry(session, workspace_id, token)
            return PersistentCredentialRecord.from_row(row) if row is not None else None

    def add(
        self,
        secret: str,
        *,
        kind: str = "password",
        username: str = "",
        origin: str = "manual",
        source_host: str = "",
        scope_hosts: Optional[Sequence[str]] = None,
        scope_ports: Optional[Sequence[int]] = None,
        protocol_hint: str = "",
        ttl_seconds: Optional[float] = None,
        notes: str = "",
    ) -> PersistentCredentialRecord:
        text = str(secret or "").strip()
        if not text:
            raise ValueError("Secret value is empty")
        self._require_encryption()
        self._ensure_schema()
        digest = hashlib.sha256(f"{self.workspace}:{kind}:{username}:{text}".encode()).hexdigest()[:12]
        credential_id = f"cred_{digest}"
        handle = f"{PERSIST_PREFIX}{kind}:{digest}"
        now = _now()
        ttl = float(ttl_seconds if ttl_seconds is not None else DEFAULT_TTL_SECONDS)
        db_manager = self._db_manager()
        with db_manager.session_scope(_DB_SESSION_KEY) as session:
            workspace_id = self._resolve_workspace_id(session)
            self._migrate_legacy_json_if_present(session, workspace_id)
            existing = session.query(VaultCredentialEntry).filter_by(
                workspace_id=workspace_id,
                credential_id=credential_id,
            ).first()
            if existing is not None:
                return PersistentCredentialRecord.from_row(existing)
            entry = VaultCredentialEntry(
                workspace_id=workspace_id,
                credential_id=credential_id,
                handle=handle,
                kind=str(kind or "password"),
                username=str(username or ""),
                secret=text,
                origin=str(origin or "manual")[:255],
                source_host=str(source_host or "")[:255],
                scope_hosts=[str(item).strip() for item in (scope_hosts or []) if str(item).strip()],
                scope_ports=[int(item) for item in (scope_ports or []) if str(item).strip().isdigit()],
                protocol_hint=str(protocol_hint or "")[:32],
                created_at=datetime.utcnow(),
                expires_at=_ts_to_dt(now + ttl) if ttl > 0 else None,
                notes=str(notes or "")[:500],
            )
            session.add(entry)
            session.flush()
            return PersistentCredentialRecord.from_row(entry)

    def revoke(self, token: str) -> bool:
        self._require_encryption()
        self._ensure_schema()
        db_manager = self._db_manager()
        with db_manager.session_scope(_DB_SESSION_KEY) as session:
            workspace_id = self._resolve_workspace_id(session)
            row = self._query_entry(session, workspace_id, token)
            if row is None:
                return False
            session.delete(row)
            return True

    def resolve_secret(self, handle: str) -> str:
        self._require_encryption()
        self._ensure_schema()
        db_manager = self._db_manager()
        with db_manager.session_scope(_DB_SESSION_KEY) as session:
            workspace_id = self._resolve_workspace_id(session)
            row = self._query_entry(session, workspace_id, handle)
            if row is None:
                return ""
            record = PersistentCredentialRecord.from_row(row)
            if record.is_expired():
                return ""
            row.last_used_at = datetime.utcnow()
            session.flush()
            return str(row.secret or "")

    def import_from_mapping(
        self,
        row: Mapping[str, Any],
        *,
        origin: str = "import",
        ttl_seconds: Optional[float] = None,
        vault_resolver: Any = None,
    ) -> Optional[PersistentCredentialRecord]:
        username = str(row.get("username") or row.get("authenticated_as") or "").strip()
        secret = str(row.get("password") or row.get("authenticated_password") or row.get("token") or "").strip()
        if secret.startswith(VAULT_PREFIX) and vault_resolver is not None:
            secret = str(vault_resolver.resolve(secret) or "").strip()
        if not secret:
            return None
        source_host = str(row.get("source_host") or row.get("host") or "").strip()
        protocol = str(row.get("protocol_hint") or row.get("protocol") or "").strip()
        scope_hosts = [source_host] if source_host else []
        return self.add(
            secret,
            kind="password" if row.get("password") or row.get("authenticated_password") else "token",
            username=username,
            origin=str(row.get("source_module") or origin)[:200],
            source_host=source_host,
            scope_hosts=scope_hosts,
            protocol_hint=protocol,
            ttl_seconds=ttl_seconds,
        )

    def import_from_kb(self, kb: Mapping[str, Any], *, vault_resolver: Any = None) -> List[PersistentCredentialRecord]:
        imported: List[PersistentCredentialRecord] = []
        for row in kb.get("credential_store") or []:
            if isinstance(row, dict):
                record = self.import_from_mapping(row, origin="discovered", vault_resolver=vault_resolver)
                if record is not None:
                    imported.append(record)
        active = kb.get("active_auth_context")
        if isinstance(active, dict):
            record = self.import_from_mapping(active, origin="active", vault_resolver=vault_resolver)
            if record is not None:
                imported.append(record)
        return imported

    def credential_allows(self, record: PersistentCredentialRecord, host: str, port: Optional[int] = None) -> Tuple[bool, str]:
        if record.is_expired():
            return False, "expired"
        host_norm = str(host or "").strip().lower()
        if record.scope_hosts:
            allowed_hosts = {item.strip().lower() for item in record.scope_hosts if item.strip()}
            if host_norm not in allowed_hosts:
                return False, "outside_credential_scope"
        if record.scope_ports and port is not None:
            if int(port) not in record.scope_ports:
                return False, "outside_credential_port_scope"
        return True, "credential_scope_ok"

    def to_scoped_credentials(self) -> List[Dict[str, Any]]:
        rows = []
        for record in self.list_records():
            rows.append({
                "credential_id": record.credential_id,
                "username": record.username,
                "password_handle": record.handle,
                "source_module": record.origin,
                "source_host": record.source_host,
                "protocol_hint": record.protocol_hint,
                "origin": "persistent_vault",
                "scope_hosts": record.scope_hosts,
                "scope_ports": record.scope_ports,
                "expires_at": record.expires_at,
            })
        return rows


_STORES: Dict[str, PersistentCredentialStore] = {}


def get_persistent_vault(framework: Any, *, workspace: str = "") -> PersistentCredentialStore:
    ws = _safe_component(
        workspace or getattr(framework, "get_current_workspace_name", lambda: "default")(),
    )
    store = _STORES.get(ws)
    if store is None:
        store = PersistentCredentialStore(framework, workspace=ws)
        _STORES[ws] = store
    return store


def is_persistent_vault_handle(value: Any) -> bool:
    return isinstance(value, str) and value.startswith(PERSIST_PREFIX)


def parse_ttl_option(raw: str) -> float:
    return _parse_ttl(raw)
