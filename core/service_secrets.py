#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Framework-level encrypted service secrets (API keys) stored in the database."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, Optional

from core.models.models import ServiceSecret

_DB_SESSION_KEY = "default"
SERVICE_VULNERS = "vulners"


class ServiceSecretStore:
    """Read/write encrypted service secrets via the workspace database + master key."""

    def __init__(self, framework: Any) -> None:
        self.framework = framework

    def _require_encryption(self) -> None:
        manager = getattr(self.framework, "encryption_manager", None)
        if manager is None or not getattr(manager, "_is_initialized", False):
            raise RuntimeError(
                "Encryption is not unlocked. Start KittySploit and unlock the master password first."
            )

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
            ServiceSecret.__table__.create(engine, checkfirst=True)
        manager = getattr(self.framework, "encryption_manager", None)
        if manager and getattr(manager, "_is_initialized", False):
            db_manager.set_encryption_manager(manager)

    def get(self, service: str) -> Optional[Dict[str, Any]]:
        """Return ``{"secret": str, "settings": dict}`` or ``None`` if missing."""
        name = str(service or "").strip().lower()
        if not name:
            return None
        self._require_encryption()
        self._ensure_schema()
        db_manager = self._db_manager()
        with db_manager.session_scope(_DB_SESSION_KEY) as session:
            row = session.query(ServiceSecret).filter_by(service=name).first()
            if row is None:
                return None
            settings = row.settings if isinstance(row.settings, dict) else {}
            return {
                "secret": str(row.secret or ""),
                "settings": dict(settings),
            }

    def set(
        self,
        service: str,
        secret: str,
        *,
        settings: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Create or update an encrypted service secret."""
        name = str(service or "").strip().lower()
        text = str(secret or "").strip()
        if not name:
            raise ValueError("Service name is required")
        if not text:
            raise ValueError("Secret value is empty")
        self._require_encryption()
        self._ensure_schema()
        payload_settings = dict(settings or {})
        db_manager = self._db_manager()
        with db_manager.session_scope(_DB_SESSION_KEY) as session:
            row = session.query(ServiceSecret).filter_by(service=name).first()
            if row is None:
                row = ServiceSecret(
                    service=name,
                    secret=text,
                    settings=payload_settings,
                    created_at=datetime.utcnow(),
                    updated_at=datetime.utcnow(),
                )
                session.add(row)
            else:
                row.secret = text
                if settings is not None:
                    merged = dict(row.settings) if isinstance(row.settings, dict) else {}
                    merged.update(payload_settings)
                    row.settings = merged
                row.updated_at = datetime.utcnow()
            session.flush()
            out_settings = row.settings if isinstance(row.settings, dict) else {}
            return {"secret": str(row.secret or ""), "settings": dict(out_settings)}

    def clear(self, service: str) -> bool:
        """Delete a service secret. Returns True if a row was removed."""
        name = str(service or "").strip().lower()
        if not name:
            return False
        self._require_encryption()
        self._ensure_schema()
        db_manager = self._db_manager()
        with db_manager.session_scope(_DB_SESSION_KEY) as session:
            row = session.query(ServiceSecret).filter_by(service=name).first()
            if row is None:
                return False
            session.delete(row)
            return True

    def exists(self, service: str) -> bool:
        name = str(service or "").strip().lower()
        if not name:
            return False
        try:
            self._require_encryption()
            self._ensure_schema()
        except RuntimeError:
            return False
        db_manager = self._db_manager()
        with db_manager.session_scope(_DB_SESSION_KEY) as session:
            return session.query(ServiceSecret).filter_by(service=name).first() is not None


def get_service_secret_store(framework: Any) -> ServiceSecretStore:
    return ServiceSecretStore(framework)
