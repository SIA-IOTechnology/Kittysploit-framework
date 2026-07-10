#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Resolve OSINT provider credentials from module options or osint.toml."""

from __future__ import annotations

from typing import Any

from core.osint.config import get_osint_config


def resolve_provider_value(name: str, explicit: Any = "") -> str:
    """Module option overrides ``~/.kittysploit/osint.toml`` provider settings."""
    text = str(explicit or "").strip()
    if text:
        return text
    return get_osint_config().get_provider_value(name)


def intelx_api_key(explicit: Any = "") -> str:
    return resolve_provider_value("intelx", explicit)


def telegram_bot_token(explicit: Any = "") -> str:
    return resolve_provider_value("telegram_bot", explicit)


def misp_endpoint() -> tuple[str, str]:
    return resolve_provider_value("misp_url"), resolve_provider_value("misp_key")


def opencti_endpoint() -> tuple[str, str]:
    return resolve_provider_value("opencti_url"), resolve_provider_value("opencti_token")


def sirius_endpoint() -> tuple[str, str]:
    return resolve_provider_value("sirius_url"), resolve_provider_value("sirius_token")
