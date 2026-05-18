"""Backward-compatible helpers for the kittyproxy marketplace app."""

from core.utils.marketplace_apps import ensure_app_path, install_hint as kittyproxy_install_hint

ensure_kittyproxy_path = lambda: ensure_app_path("kittyproxy")
