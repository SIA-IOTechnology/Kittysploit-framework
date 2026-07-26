"""Backward-compatible helpers for the kittyproxy marketplace app."""

from core.utils.marketplace_apps import ensure_app_path, install_hint


def ensure_kittyproxy_path() -> bool:
    return ensure_app_path("kittyproxy")


def kittyproxy_install_hint() -> str:
    return install_hint("kittyproxy")
