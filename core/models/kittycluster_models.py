#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Database models for kittyCluster (per workspace DB)."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import Boolean, Column, DateTime, Integer, String, Text

from core.models.encrypted_fields import EncryptedFieldMixin, EncryptedString, EncryptedText
from core.models.models import Base


class KittyClusterNode(Base, EncryptedFieldMixin):
    __tablename__ = "kittycluster_nodes"

    id = Column(String(64), primary_key=True)
    name = Column(String(80), nullable=False, index=True)
    base_url = Column(EncryptedText, nullable=False)
    token = Column(EncryptedString(1000))
    role = Column(String(40), default="slave", index=True)
    tags = Column(Text, default="")
    note = Column(Text, default="")
    enabled = Column(Boolean, default=True)
    tls_no_verify = Column(Boolean, default=False)
    relay_via = Column(String(64))
    downstream_url = Column(EncryptedText)

    status = Column(String(50), default="unknown")
    last_seen = Column(String(64))
    version = Column(String(64))
    last_error = Column(Text)

    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class KittyClusterCommandRun(Base, EncryptedFieldMixin):
    __tablename__ = "kittycluster_command_runs"

    id = Column(String(64), primary_key=True)
    command = Column(EncryptedText, nullable=False)
    target = Column(String(32), default="all")
    target_ids = Column(EncryptedText)  # JSON string

    started_at = Column(DateTime, default=datetime.utcnow, index=True)
    finished_at = Column(DateTime)

    total = Column(Integer, default=0)
    ok = Column(Integer, default=0)
    failed = Column(Integer, default=0)

    # Encrypted JSON payload of results (stdout/stderr may be sensitive)
    results_json = Column(EncryptedText)

