#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Data models for the Registry Marketplace
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
    """Extension publisher"""
    __tablename__ = 'registry_publishers'
    
    id = Column(Integer, primary_key=True)
    name = Column(String(255), unique=True, nullable=False, index=True)
    email = Column(String(255), nullable=False)
    public_key = Column(Text, nullable=False)  # Public key for signature verification
    kyc_status = Column(String(50), default='pending')  # pending, verified, rejected
    kyc_data = Column(JSON)  # KYC data (encrypted if necessary)
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
    """Extension in the registry"""
    __tablename__ = 'registry_extensions'
    
    id = Column(Integer, primary_key=True)
    extension_id = Column(String(255), unique=True, nullable=False, index=True)  # Unique extension ID
    name = Column(String(255), nullable=False)
    description = Column(Text)
    extension_type = Column(String(50), nullable=False)  # module, plugin, UI, middleware
    publisher_id = Column(Integer, ForeignKey('registry_publishers.id'), nullable=True)  # Optional - for compatibility
    created_by_user_id = Column(Integer, ForeignKey('registry_users.id'), nullable=False, index=True)  # ID of user who created the extension (via API key) - REQUIRED
    price = Column(Float, default=0.0)  # Price in default currency
    currency = Column(String(10), default='USD')
    license_type = Column(String(50), default='MIT')  # MIT, GPL, proprietary, etc.
    is_free = Column(Boolean, default=True)
    is_revoked = Column(Boolean, default=False)
    revoked_reason = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships - defined after all classes to avoid order issues
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
    """Extension version"""
    __tablename__ = 'registry_extension_versions'
    
    id = Column(Integer, primary_key=True)
    extension_id = Column(Integer, ForeignKey('registry_extensions.id'), nullable=False)
    version = Column(String(50), nullable=False)  # Semver
    bundle_hash = Column(String(64), nullable=False)  # SHA256 of bundle
    bundle_path = Column(String(500))  # Path to bundle on server
    bundle_size = Column(Integer)  # Size in bytes
    manifest_content = Column(Text)  # Content of extension.toml manifest
    signature = Column(Text)  # Manifest signature
    kittysploit_min = Column(String(50))  # Minimum required version
    kittysploit_max = Column(String(50))  # Maximum supported version
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
    """Wallet for monetization"""
    __tablename__ = 'registry_wallets'
    
    id = Column(Integer, primary_key=True)
    user_id = Column(String(255), nullable=False, index=True)  # User ID (can be publisher_id or other)
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
    """Financial transaction"""
    __tablename__ = 'registry_transactions'
    
    id = Column(Integer, primary_key=True)
    wallet_id = Column(Integer, ForeignKey('registry_wallets.id'), nullable=False)
    transaction_type = Column(String(50), nullable=False)  # topup, purchase, payout, refund
    amount = Column(Float, nullable=False)
    currency = Column(String(10), default='USD')
    status = Column(String(50), default='pending')  # pending, completed, failed, refunded
    external_id = Column(String(255))  # External transaction ID (Stripe, etc.)
    extension_id = Column(Integer, ForeignKey('registry_extensions.id'))  # For purchase
    transaction_metadata = Column(JSON)  # Additional data (renamed because 'metadata' is reserved)
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
    """Extension usage license"""
    __tablename__ = 'registry_licenses'
    
    id = Column(Integer, primary_key=True)
    extension_id = Column(Integer, ForeignKey('registry_extensions.id'), nullable=False)
    user_id = Column(String(255), nullable=False, index=True)
    version = Column(String(50))  # Purchased version
    transaction_id = Column(Integer, ForeignKey('registry_transactions.id'))
    is_active = Column(Boolean, default=True)
    expires_at = Column(DateTime)  # For temporary licenses
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationships - back_populates will be configured after definition
    extension = relationship("Extension")
    transaction = relationship("Transaction")
    
    __table_args__ = (
        UniqueConstraint('extension_id', 'user_id', 'version', name='uq_license'),
        Index('idx_license_user_active', 'user_id', 'is_active'),
    )
    
    def __repr__(self):
        return f"<License(extension_id={self.extension_id}, user_id='{self.user_id}', active={self.is_active})>"


class User(Base):
    """Registry user"""
    __tablename__ = 'registry_users'
    
    id = Column(Integer, primary_key=True)
    email = Column(String(255), unique=True, nullable=False, index=True)
    password_hash = Column(String(255), nullable=False)  # Bcrypt password hash
    username = Column(String(255), unique=True, nullable=True, index=True)
    is_active = Column(Boolean, default=True)
    is_admin = Column(Boolean, default=False)
    public_key = Column(Text, nullable=True)  # Public key for signature verification (auto-generated)
    private_key_path = Column(String(500), nullable=True)  # Path to private key (stored locally)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    last_login = Column(DateTime)
    
    # Relationships
    api_keys = relationship("ApiKey", back_populates="user", cascade="all, delete-orphan")
    
    def __repr__(self):
        return f"<User(email='{self.email}', active={self.is_active})>"


class ApiKey(Base):
    """API key for authentication"""
    __tablename__ = 'registry_api_keys'
    
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('registry_users.id'), nullable=False, index=True)
    key_hash = Column(String(255), nullable=False, unique=True, index=True)  # API key hash
    key_prefix = Column(String(20), nullable=False)  # Prefix for display (e.g: "ks_abc123...")
    name = Column(String(255))  # Optional name to identify the key
    is_active = Column(Boolean, default=True)
    last_used = Column(DateTime)
    expires_at = Column(DateTime)  # Optional: key expiration
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
    """Audit log for all marketplace actions"""
    __tablename__ = 'registry_audit_logs'
    
    id = Column(Integer, primary_key=True)
    action = Column(String(100), nullable=False)  # publish, install, purchase, revoke, etc.
    actor_id = Column(String(255), nullable=False, index=True)
    actor_type = Column(String(50), nullable=False)  # publisher, user, admin, system
    target_type = Column(String(50))  # extension, version, transaction, etc.
    target_id = Column(String(255))
    details = Column(JSON)  # Action details
    ip_address = Column(String(45))  # IPv4 or IPv6
    user_agent = Column(String(500))
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    
    __table_args__ = (
        CheckConstraint("actor_type IN ('publisher', 'user', 'admin', 'system')", name='check_actor_type'),
        Index('idx_audit_action_created', 'action', 'created_at'),
    )
    
    def __repr__(self):
        return f"<AuditLog(action='{self.action}', actor='{self.actor_id}')>"


# Configure licenses relationship after all classes are defined
# This avoids SQLAlchemy definition order issues
Extension.licenses = relationship("License", back_populates="extension", cascade="all, delete-orphan")
License.extension = relationship("Extension", back_populates="licenses")

