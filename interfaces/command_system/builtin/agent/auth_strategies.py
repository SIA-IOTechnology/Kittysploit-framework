#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Pluggable auth override and bruteforce-field strategies.

Add a new :class:`AuthOverrideStrategy` or :class:`BruteforceFieldStrategy` instead of
growing monolithic inference in the workflow core.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Protocol, Tuple, runtime_checkable


@dataclass(frozen=True)
class AuthOverrideBuildContext:
    """Inputs for :meth:`AuthOverrideStrategy.build` (module path + KB session material)."""

    module_instance: Any
    module_path: str
    auth_context: Dict[str, Any]
    username: str
    password: str
    login_path: str
    final_path: str
    session_cookie: str

    @property
    def module_path_low(self) -> str:
        return self.module_path.lower()


@runtime_checkable
class AuthOverrideStrategy(Protocol):
    def supports(self, module_path: str) -> bool:
        ...

    def build(self, ctx: AuthOverrideBuildContext) -> Dict[str, Any]:
        ...


class DefaultAuthOverrideStrategy:
    """Generic attribute wiring (username/password/session, admin/resource paths)."""

    def supports(self, module_path: str) -> bool:
        return True

    def build(self, ctx: AuthOverrideBuildContext) -> Dict[str, Any]:
        overrides: Dict[str, Any] = {}
        mi = ctx.module_instance
        username = ctx.username
        password = ctx.password
        login_path = ctx.login_path
        final_path = ctx.final_path
        session_cookie = ctx.session_cookie

        if username:
            for attr in ("username", "admin_username", "flowise_username"):
                if hasattr(mi, attr):
                    overrides[attr] = username
        if password:
            for attr in ("password", "admin_password", "flowise_password"):
                if hasattr(mi, attr):
                    overrides[attr] = password
        if login_path and "admin_login_bruteforce" in ctx.module_path_low:
            overrides["path"] = login_path
        if session_cookie and hasattr(mi, "session_cookie"):
            overrides["session_cookie"] = session_cookie

        if final_path:
            if hasattr(mi, "console_path") and "/console" in final_path.lower():
                overrides.setdefault("console_path", final_path)

        admin_candidates = [final_path, login_path]
        admin_path = ""
        for candidate in admin_candidates:
            low = str(candidate).lower()
            if "/admin" in low:
                admin_path = candidate.split("?", 1)[0]
                if low.endswith("/login"):
                    admin_path = admin_path.rsplit("/login", 1)[0] or "/admin"
                break
        if admin_path and hasattr(mi, "admin_path"):
            overrides.setdefault("admin_path", admin_path)

        if hasattr(mi, "resource_path"):
            resource_path = ""
            if "/resources" in str(final_path).lower():
                resource_path = final_path.split("?", 1)[0]
            elif admin_path:
                resource_path = f"{admin_path.rstrip('/')}/resources"
            if resource_path:
                overrides.setdefault("resource_path", resource_path)

        if hasattr(mi, "form_path") and final_path and "/form" in final_path.lower():
            overrides.setdefault("form_path", final_path.split("?", 1)[0])

        # Avoid poisoning unauthenticated exploit paths with the login form itself.
        if login_path and final_path and final_path == login_path:
            for attr in ("path", "exploit_path"):
                if overrides.get(attr) == login_path and attr in overrides:
                    del overrides[attr]

        return overrides


class AlchemyAuthOverrideStrategy:
    """GraphQL Alchemy-style modules: prefer session cookie when present."""

    def supports(self, module_path: str) -> bool:
        return "/alchemy" in module_path.lower()

    def build(self, ctx: AuthOverrideBuildContext) -> Dict[str, Any]:
        if not ctx.session_cookie or not hasattr(ctx.module_instance, "session_cookie"):
            return {}
        return {"session_cookie": ctx.session_cookie}


class LimeSurveyAuthOverrideStrategy:
    """LimeSurvey scanners expect explicit username/password when we have them."""

    def supports(self, module_path: str) -> bool:
        return "limesurvey" in module_path.lower()

    def build(self, ctx: AuthOverrideBuildContext) -> Dict[str, Any]:
        out: Dict[str, Any] = {}
        if ctx.username:
            out.setdefault("username", ctx.username)
        if ctx.password:
            out.setdefault("password", ctx.password)
        return out


class DVWAAuthOverrideStrategy:
    """DVWA modules may live at /dvwa or directly at the web root."""

    def supports(self, module_path: str) -> bool:
        low = module_path.lower()
        return "dvwa_" in low or "/dvwa" in low

    def _set_base_options(self, ctx: AuthOverrideBuildContext, out: Dict[str, Any], base_path: str) -> Dict[str, Any]:
        """Populate whichever base-path option names the target module actually exposes."""
        if hasattr(ctx.module_instance, "base_path"):
            out["base_path"] = base_path
        if hasattr(ctx.module_instance, "path"):
            out["path"] = base_path
        return out

    def build(self, ctx: AuthOverrideBuildContext) -> Dict[str, Any]:
        out: Dict[str, Any] = {}
        login_path = str(ctx.login_path or "").strip()
        final_path = str(ctx.final_path or "").strip()
        candidates = [login_path, final_path]
        for candidate in candidates:
            low = candidate.lower()
            if "/dvwa/" in low or low == "/dvwa":
                return self._set_base_options(ctx, out, "/dvwa")
        if login_path.startswith("/login.php") or final_path.startswith("/index.php"):
            return self._set_base_options(ctx, out, "/")
        return out


AUTH_OVERRIDE_STRATEGIES: Tuple[AuthOverrideStrategy, ...] = (
    DefaultAuthOverrideStrategy(),
    AlchemyAuthOverrideStrategy(),
    LimeSurveyAuthOverrideStrategy(),
    DVWAAuthOverrideStrategy(),
)


def compose_auth_option_overrides(
    ctx: AuthOverrideBuildContext,
    strategies: Tuple[AuthOverrideStrategy, ...] = AUTH_OVERRIDE_STRATEGIES,
) -> Dict[str, Any]:
    merged: Dict[str, Any] = {}
    for strat in strategies:
        if strat.supports(ctx.module_path):
            merged.update(strat.build(ctx))
    return merged


# --- Bruteforce form field inference (admin_login_bruteforce) ---


@runtime_checkable
class BruteforceFieldStrategy(Protocol):
    def supports(self, login_path: str) -> bool:
        ...

    def build(self) -> Dict[str, Any]:
        ...


class WordPressLoginBruteforceStrategy:
    def supports(self, login_path: str) -> bool:
        low = login_path.lower().split("?", 1)[0]
        return "wp-login" in low or low.endswith("/wp-login.php")

    def build(self) -> Dict[str, Any]:
        return {"username_field": "log", "password_field": "pwd"}


class DrupalLoginBruteforceStrategy:
    def supports(self, login_path: str) -> bool:
        low = login_path.lower().split("?", 1)[0]
        return "/user/login" in low or low.rstrip("/").endswith("/user/login")

    def build(self) -> Dict[str, Any]:
        return {"username_field": "name", "password_field": "pass"}


BRUTEFORCE_FIELD_STRATEGIES: Tuple[BruteforceFieldStrategy, ...] = (
    WordPressLoginBruteforceStrategy(),
    DrupalLoginBruteforceStrategy(),
)


def infer_bruteforce_field_overrides(login_path: str) -> Dict[str, Any]:
    """Map known CMS login routes to typical form field names for admin_login_bruteforce."""
    if not login_path:
        return {}
    for strat in BRUTEFORCE_FIELD_STRATEGIES:
        if strat.supports(login_path):
            return strat.build()
    return {}
