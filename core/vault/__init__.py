#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Persistent encrypted credential vault."""

from core.vault.agent_bridge import (
    bind_agent_runtime,
    capture_discovered_credentials,
    resolve_agent_framework,
    sync_agent_vault_context,
)
from core.vault.persistent_store import PersistentCredentialStore, get_persistent_vault

__all__ = [
    "PersistentCredentialStore",
    "get_persistent_vault",
    "bind_agent_runtime",
    "capture_discovered_credentials",
    "resolve_agent_framework",
    "sync_agent_vault_context",
]
