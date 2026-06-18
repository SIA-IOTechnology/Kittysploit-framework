#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Server-side registry marketplace service (self-hosted registry mode)."""

from __future__ import annotations

import logging
import os
from datetime import datetime
from typing import Any, Dict, List, Optional

from sqlalchemy import or_
from sqlalchemy.orm import Session

from core.registry.models import (
    AuditLog,
    Extension,
    ExtensionVersion,
    License,
    Publisher,
    Transaction,
    Wallet,
)
from core.registry.signature import RegistrySignatureManager

logger = logging.getLogger(__name__)


class RegistryService:
    """Business logic for the local registry marketplace (server mode)."""

    def __init__(
        self,
        db_session: Session,
        signature_manager: Optional[RegistrySignatureManager] = None,
        bundles_dir: Optional[str] = None,
    ):
        self.db = db_session
        self.signature_manager = signature_manager or RegistrySignatureManager()
        self.bundles_dir = bundles_dir or os.environ.get(
            "KITTYSPLOIT_REGISTRY_BUNDLES_DIR",
            os.path.join(os.path.expanduser("~"), ".kittysploit", "registry", "bundles"),
        )
        os.makedirs(self.bundles_dir, exist_ok=True)

    def list_extensions(
        self,
        extension_type: Optional[str] = None,
        is_free: Optional[bool] = None,
        search: Optional[str] = None,
        page: int = 1,
        per_page: int = 20,
    ) -> Dict[str, Any]:
        query = self.db.query(Extension).filter(Extension.is_revoked.is_(False))

        if extension_type:
            query = query.filter(Extension.extension_type == extension_type)
        if is_free is not None:
            query = query.filter(Extension.is_free.is_(is_free))
        if search:
            pattern = f"%{search.strip()}%"
            query = query.filter(
                or_(
                    Extension.name.ilike(pattern),
                    Extension.description.ilike(pattern),
                    Extension.extension_id.ilike(pattern),
                )
            )

        total = query.count()
        page = max(1, int(page or 1))
        per_page = max(1, min(int(per_page or 20), 100))
        offset = (page - 1) * per_page

        extensions = (
            query.order_by(Extension.name.asc())
            .offset(offset)
            .limit(per_page)
            .all()
        )

        return {
            "extensions": [self._extension_summary(ext) for ext in extensions],
            "total": total,
            "page": page,
            "per_page": per_page,
        }

    def get_extension(self, extension_id: str) -> Optional[Dict[str, Any]]:
        extension = self._get_extension(extension_id)
        if not extension:
            return None
        return self._extension_detail(extension)

    def get_extension_bundle(
        self,
        extension_id: str,
        version: Optional[str] = None,
    ) -> Optional[str]:
        extension = self._get_extension(extension_id)
        if not extension or extension.is_revoked:
            return None

        ext_version = self._resolve_version(extension, version)
        if not ext_version or not ext_version.bundle_path:
            return None

        bundle_path = self._resolve_bundle_path(ext_version.bundle_path)
        if not bundle_path or not os.path.isfile(bundle_path):
            return None

        if ext_version.bundle_hash and self.signature_manager:
            if not self.signature_manager.verify_bundle_integrity(
                bundle_path, ext_version.bundle_hash
            ):
                logger.warning(
                    "Bundle integrity check failed for %s v%s",
                    extension_id,
                    ext_version.version,
                )
                return None

        ext_version.download_count = (ext_version.download_count or 0) + 1
        self.db.commit()
        return bundle_path

    def purchase_extension(
        self,
        extension_id: str,
        user_id: str,
        version: Optional[str] = None,
    ) -> Optional[License]:
        if not user_id:
            return None

        extension = self._get_extension(extension_id)
        if not extension or extension.is_revoked:
            return None

        ext_version = self._resolve_version(extension, version)
        version_label = ext_version.version if ext_version else (version or "latest")

        existing = (
            self.db.query(License)
            .filter(
                License.extension_id == extension.id,
                License.user_id == user_id,
                License.version == version_label,
                License.is_active.is_(True),
            )
            .first()
        )
        if existing:
            return existing

        transaction = None
        if not extension.is_free and extension.price > 0:
            wallet = self._get_or_create_wallet(user_id, "user")
            if wallet.balance < extension.price:
                return None

            wallet.balance -= extension.price
            transaction = Transaction(
                wallet_id=wallet.id,
                transaction_type="purchase",
                amount=extension.price,
                currency=extension.currency,
                status="completed",
                extension_id=extension.id,
                completed_at=datetime.utcnow(),
                transaction_metadata={"extension_id": extension.extension_id},
            )
            self.db.add(transaction)
            self.db.flush()

        license_obj = License(
            extension_id=extension.id,
            user_id=user_id,
            version=version_label,
            transaction_id=transaction.id if transaction else None,
            is_active=True,
        )
        self.db.add(license_obj)
        self._audit(
            action="purchase",
            actor_id=user_id,
            actor_type="user",
            target_type="extension",
            target_id=extension.extension_id,
            details={"version": version_label, "price": extension.price},
        )
        self.db.commit()
        return license_obj

    def register_publisher(
        self,
        name: str,
        email: str,
        public_key: str,
        kyc_data: Optional[Dict[str, Any]] = None,
    ) -> Optional[Publisher]:
        if not all([name, email, public_key]):
            return None

        existing = self.db.query(Publisher).filter(Publisher.name == name).first()
        if existing:
            return None

        publisher = Publisher(
            name=name.strip(),
            email=email.strip(),
            public_key=public_key.strip(),
            kyc_data=kyc_data or {},
            kyc_status="pending",
        )
        self.db.add(publisher)
        self._audit(
            action="register_publisher",
            actor_id=name,
            actor_type="publisher",
            target_type="publisher",
            target_id=name,
        )
        self.db.commit()

        try:
            self.signature_manager.add_trusted_publisher(name, public_key)
        except Exception as exc:
            logger.warning("Could not add publisher to trust store: %s", exc)

        return publisher

    def revoke_extension(
        self,
        extension_id: str,
        reason: str,
        actor_id: str,
    ) -> bool:
        extension = self._get_extension(extension_id)
        if not extension:
            return False

        extension.is_revoked = True
        extension.revoked_reason = reason or "No reason provided"
        extension.updated_at = datetime.utcnow()
        self._audit(
            action="revoke",
            actor_id=actor_id or "admin",
            actor_type="admin",
            target_type="extension",
            target_id=extension.extension_id,
            details={"reason": extension.revoked_reason},
        )
        self.db.commit()
        return True

    def _get_extension(self, extension_id: str) -> Optional[Extension]:
        if not extension_id:
            return None
        return (
            self.db.query(Extension)
            .filter(Extension.extension_id == extension_id)
            .first()
        )

    def _resolve_version(
        self,
        extension: Extension,
        version: Optional[str],
    ) -> Optional[ExtensionVersion]:
        query = self.db.query(ExtensionVersion).filter(
            ExtensionVersion.extension_id == extension.id
        )
        if version:
            return query.filter(ExtensionVersion.version == version).first()

        latest = query.filter(ExtensionVersion.is_latest.is_(True)).first()
        if latest:
            return latest
        return query.order_by(ExtensionVersion.created_at.desc()).first()

    def _resolve_bundle_path(self, bundle_path: str) -> Optional[str]:
        if not bundle_path:
            return None
        if os.path.isabs(bundle_path) and os.path.isfile(bundle_path):
            return bundle_path

        candidates = [
            os.path.join(self.bundles_dir, bundle_path),
            os.path.join(self.bundles_dir, os.path.basename(bundle_path)),
        ]
        for candidate in candidates:
            if os.path.isfile(candidate):
                return candidate
        return None

    def _get_or_create_wallet(self, user_id: str, user_type: str) -> Wallet:
        wallet = (
            self.db.query(Wallet)
            .filter(Wallet.user_id == user_id, Wallet.user_type == user_type)
            .first()
        )
        if wallet:
            return wallet

        wallet = Wallet(user_id=user_id, user_type=user_type, balance=0.0)
        self.db.add(wallet)
        self.db.flush()
        return wallet

    def _latest_version(self, extension: Extension) -> Optional[ExtensionVersion]:
        return self._resolve_version(extension, None)

    def _extension_summary(self, extension: Extension) -> Dict[str, Any]:
        latest = self._latest_version(extension)
        publisher_name = extension.publisher.name if extension.publisher else None
        return {
            "id": extension.extension_id,
            "name": extension.name,
            "description": extension.description or "",
            "type": extension.extension_type,
            "extension_type": extension.extension_type,
            "price": extension.price,
            "currency": extension.currency,
            "is_free": extension.is_free,
            "license_type": extension.license_type,
            "is_revoked": extension.is_revoked,
            "version": latest.version if latest else None,
            "publisher": publisher_name,
            "author": {"username": publisher_name or "Unknown"},
            "downloads": latest.download_count if latest else 0,
            "can_download": extension.is_free,
            "has_purchased": extension.is_free,
        }

    def _extension_detail(self, extension: Extension) -> Dict[str, Any]:
        detail = self._extension_summary(extension)
        versions = (
            self.db.query(ExtensionVersion)
            .filter(ExtensionVersion.extension_id == extension.id)
            .order_by(ExtensionVersion.created_at.desc())
            .all()
        )
        detail["versions"] = [
            {
                "version": item.version,
                "is_latest": item.is_latest,
                "bundle_size": item.bundle_size,
                "download_count": item.download_count or 0,
                "kittysploit_min": item.kittysploit_min,
                "kittysploit_max": item.kittysploit_max,
                "created_at": item.created_at.isoformat() if item.created_at else None,
            }
            for item in versions
        ]
        detail["created_at"] = (
            extension.created_at.isoformat() if extension.created_at else None
        )
        detail["updated_at"] = (
            extension.updated_at.isoformat() if extension.updated_at else None
        )
        return detail

    def _audit(
        self,
        action: str,
        actor_id: str,
        actor_type: str,
        target_type: Optional[str] = None,
        target_id: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        self.db.add(
            AuditLog(
                action=action,
                actor_id=actor_id,
                actor_type=actor_type,
                target_type=target_type,
                target_id=target_id,
                details=details or {},
            )
        )
