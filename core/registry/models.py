#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Modèles de données pour le Registry Marketplace
"""

from sqlalchemy import (
    Column, Integer, String, Text, DateTime, ForeignKey, Boolean, 
    Float, Index, UniqueConstraint, CheckConstraint, JSON
)
from sqlalchemy.orm import relationship
from datetime import datetime
from core.models.models import Base
from core.models.encrypted_fields import EncryptedString, EncryptedText, EncryptedFieldMixin


class Publisher(Base):
    """Éditeur d'extensions"""
    __tablename__ = 'registry_publishers'
    
    id = Column(Integer, primary_key=True)
    name = Column(String(255), unique=True, nullable=False, index=True)
    email = Column(String(255), nullable=False)
    public_key = Column(Text, nullable=False)  # Clé publique pour vérification signatures
    kyc_status = Column(String(50), default='pending')  # pending, verified, rejected
    kyc_data = Column(JSON)  # Données KYC (chiffrées si nécessaire)
    wallet_id = Column(Integer, ForeignKey('registry_wallets.id'))
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    is_active = Column(Boolean, default=True)
    
    # Relationships
    extensions = relationship("Extension", back_populates="publisher", cascade="all, delete-orphan")
    wallet = relationship("Wallet", back_populates="publisher")
    
    __table_args__ = (
        CheckConstraint("kyc_status IN ('pending', 'verified', 'rejected')", name='check_kyc_status'),
    )
    
    def __repr__(self):
        return f"<Publisher(name='{self.name}', kyc={self.kyc_status})>"


class Extension(Base):
    """Extension dans le registry"""
    __tablename__ = 'registry_extensions'
    
    id = Column(Integer, primary_key=True)
    extension_id = Column(String(255), unique=True, nullable=False, index=True)  # ID unique de l'extension
    name = Column(String(255), nullable=False)
    description = Column(Text)
    extension_type = Column(String(50), nullable=False)  # module, plugin, UI, middleware
    publisher_id = Column(Integer, ForeignKey('registry_publishers.id'), nullable=True)  # Optionnel - pour compatibilité
    created_by_user_id = Column(Integer, ForeignKey('registry_users.id'), nullable=False, index=True)  # ID de l'utilisateur qui a créé l'extension (via API key) - REQUIS
    price = Column(Float, default=0.0)  # Prix en devise par défaut
    currency = Column(String(10), default='USD')
    license_type = Column(String(50), default='MIT')  # MIT, GPL, proprietary, etc.
    is_free = Column(Boolean, default=True)
    is_revoked = Column(Boolean, default=False)
    revoked_reason = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships - définies après toutes les classes pour éviter les problèmes d'ordre
    publisher = relationship("Publisher", back_populates="extensions")
    versions = relationship("ExtensionVersion", back_populates="extension", cascade="all, delete-orphan")
    
    __table_args__ = (
        CheckConstraint("extension_type IN ('module', 'plugin', 'UI', 'middleware')", name='check_extension_type'),
        CheckConstraint("price >= 0", name='check_price_positive'),
        Index('idx_extension_type_revoked', 'extension_type', 'is_revoked'),
    )
    
    def __repr__(self):
        return f"<Extension(id='{self.extension_id}', type={self.extension_type})>"


class ExtensionVersion(Base):
    """Version d'une extension"""
    __tablename__ = 'registry_extension_versions'
    
    id = Column(Integer, primary_key=True)
    extension_id = Column(Integer, ForeignKey('registry_extensions.id'), nullable=False)
    version = Column(String(50), nullable=False)  # Semver
    bundle_hash = Column(String(64), nullable=False)  # SHA256 du bundle
    bundle_path = Column(String(500))  # Chemin vers le bundle sur le serveur
    bundle_size = Column(Integer)  # Taille en bytes
    manifest_content = Column(Text)  # Contenu du manifest extension.toml
    signature = Column(Text)  # Signature du manifest
    kittysploit_min = Column(String(50))  # Version minimale requise
    kittysploit_max = Column(String(50))  # Version maximale supportée
    is_latest = Column(Boolean, default=False)
    download_count = Column(Integer, default=0)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    extension = relationship("Extension", back_populates="versions")
    
    __table_args__ = (
        UniqueConstraint('extension_id', 'version', name='uq_extension_version'),
        Index('idx_version_latest', 'extension_id', 'is_latest'),
    )
    
    def __repr__(self):
        return f"<ExtensionVersion(extension_id={self.extension_id}, version='{self.version}')>"


class Wallet(Base, EncryptedFieldMixin):
    """Portefeuille pour monétisation"""
    __tablename__ = 'registry_wallets'
    
    id = Column(Integer, primary_key=True)
    user_id = Column(String(255), nullable=False, index=True)  # ID utilisateur (peut être publisher_id ou autre)
    user_type = Column(String(50), nullable=False)  # publisher, user
    balance = Column(Float, default=0.0)
    currency = Column(String(10), default='USD')
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    publisher = relationship("Publisher", back_populates="wallet", uselist=False)
    transactions = relationship("Transaction", back_populates="wallet", cascade="all, delete-orphan")
    
    __table_args__ = (
        CheckConstraint("user_type IN ('publisher', 'user')", name='check_user_type'),
        CheckConstraint("balance >= 0", name='check_balance_positive'),
        UniqueConstraint('user_id', 'user_type', name='uq_wallet_user'),
    )
    
    def __repr__(self):
        return f"<Wallet(user_id='{self.user_id}', balance={self.balance})>"


class Transaction(Base):
    """Transaction financière"""
    __tablename__ = 'registry_transactions'
    
    id = Column(Integer, primary_key=True)
    wallet_id = Column(Integer, ForeignKey('registry_wallets.id'), nullable=False)
    transaction_type = Column(String(50), nullable=False)  # topup, purchase, payout, refund
    amount = Column(Float, nullable=False)
    currency = Column(String(10), default='USD')
    status = Column(String(50), default='pending')  # pending, completed, failed, refunded
    external_id = Column(String(255))  # ID transaction externe (Stripe, etc.)
    extension_id = Column(Integer, ForeignKey('registry_extensions.id'))  # Pour purchase
    transaction_metadata = Column(JSON)  # Données additionnelles (renommé car 'metadata' est réservé)
    created_at = Column(DateTime, default=datetime.utcnow)
    completed_at = Column(DateTime)
    
    # Relationships
    wallet = relationship("Wallet", back_populates="transactions")
    extension = relationship("Extension")
    
    __table_args__ = (
        CheckConstraint("transaction_type IN ('topup', 'purchase', 'payout', 'refund')", name='check_transaction_type'),
        CheckConstraint("status IN ('pending', 'completed', 'failed', 'refunded')", name='check_transaction_status'),
        Index('idx_transaction_type_status', 'transaction_type', 'status'),
    )
    
    def __repr__(self):
        return f"<Transaction(type='{self.transaction_type}', amount={self.amount}, status='{self.status}')>"


class License(Base):
    """Licence d'utilisation d'une extension"""
    __tablename__ = 'registry_licenses'
    
    id = Column(Integer, primary_key=True)
    extension_id = Column(Integer, ForeignKey('registry_extensions.id'), nullable=False)
    user_id = Column(String(255), nullable=False, index=True)
    version = Column(String(50))  # Version achetée
    transaction_id = Column(Integer, ForeignKey('registry_transactions.id'))
    is_active = Column(Boolean, default=True)
    expires_at = Column(DateTime)  # Pour licences temporaires
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationships - back_populates sera configuré après la définition
    extension = relationship("Extension")
    transaction = relationship("Transaction")
    
    __table_args__ = (
        UniqueConstraint('extension_id', 'user_id', 'version', name='uq_license'),
        Index('idx_license_user_active', 'user_id', 'is_active'),
    )
    
    def __repr__(self):
        return f"<License(extension_id={self.extension_id}, user_id='{self.user_id}', active={self.is_active})>"


class User(Base):
    """Utilisateur du registry"""
    __tablename__ = 'registry_users'
    
    id = Column(Integer, primary_key=True)
    email = Column(String(255), unique=True, nullable=False, index=True)
    password_hash = Column(String(255), nullable=False)  # Hash bcrypt du mot de passe
    username = Column(String(255), unique=True, nullable=True, index=True)
    is_active = Column(Boolean, default=True)
    is_admin = Column(Boolean, default=False)
    public_key = Column(Text, nullable=True)  # Clé publique pour vérification signatures (générée automatiquement)
    private_key_path = Column(String(500), nullable=True)  # Chemin vers la clé privée (stockée localement)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    last_login = Column(DateTime)
    
    # Relationships
    api_keys = relationship("ApiKey", back_populates="user", cascade="all, delete-orphan")
    
    def __repr__(self):
        return f"<User(email='{self.email}', active={self.is_active})>"


class ApiKey(Base):
    """Clé API pour authentification"""
    __tablename__ = 'registry_api_keys'
    
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('registry_users.id'), nullable=False, index=True)
    key_hash = Column(String(255), nullable=False, unique=True, index=True)  # Hash de la clé API
    key_prefix = Column(String(20), nullable=False)  # Préfixe pour affichage (ex: "ks_abc123...")
    name = Column(String(255))  # Nom optionnel pour identifier la clé
    is_active = Column(Boolean, default=True)
    last_used = Column(DateTime)
    expires_at = Column(DateTime)  # Optionnel : expiration de la clé
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    user = relationship("User", back_populates="api_keys")
    
    __table_args__ = (
        Index('idx_api_key_hash', 'key_hash'),
        Index('idx_api_key_user_active', 'user_id', 'is_active'),
    )
    
    def __repr__(self):
        return f"<ApiKey(user_id={self.user_id}, prefix='{self.key_prefix}', active={self.is_active})>"


class AuditLog(Base):
    """Journal d'audit pour toutes les actions du marketplace"""
    __tablename__ = 'registry_audit_logs'
    
    id = Column(Integer, primary_key=True)
    action = Column(String(100), nullable=False)  # publish, install, purchase, revoke, etc.
    actor_id = Column(String(255), nullable=False, index=True)
    actor_type = Column(String(50), nullable=False)  # publisher, user, admin, system
    target_type = Column(String(50))  # extension, version, transaction, etc.
    target_id = Column(String(255))
    details = Column(JSON)  # Détails de l'action
    ip_address = Column(String(45))  # IPv4 ou IPv6
    user_agent = Column(String(500))
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    
    __table_args__ = (
        CheckConstraint("actor_type IN ('publisher', 'user', 'admin', 'system')", name='check_actor_type'),
        Index('idx_audit_action_created', 'action', 'created_at'),
    )
    
    def __repr__(self):
        return f"<AuditLog(action='{self.action}', actor='{self.actor_id}')>"


# Configurer la relation licenses après que toutes les classes soient définies
# Cela évite les problèmes d'ordre de définition avec SQLAlchemy
Extension.licenses = relationship("License", back_populates="extension", cascade="all, delete-orphan")
License.extension = relationship("Extension", back_populates="licenses")

