#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Auth context extraction, KB merge/score, session seeding, and option override inference."""

from __future__ import annotations

from typing import Any, Callable, Dict, List, Optional

from interfaces.command_system.builtin.agent.agent_constants import (
    AUTH_PATH_MARKERS,
    LOGIN_PATH_PRIORITY,
    SESSION_COOKIE_NAME_MARKERS,
)
from interfaces.command_system.builtin.agent.auth_strategies import (
    AuthOverrideBuildContext,
    compose_auth_option_overrides,
    infer_bruteforce_field_overrides,
)
from interfaces.command_system.builtin.agent.state import AgentState


class AuthContextOperations:
    """Dedicated auth logic (keeps :class:`AgentWorkflowCore` slimmer)."""

    def __init__(self, normalize_relative_path: Callable[[Any], str]) -> None:
        self._normalize_relative_path = normalize_relative_path

    def sanitize_cookie_map(self, raw: Any) -> Dict[str, str]:
        if not isinstance(raw, dict):
            return {}
        cookies: Dict[str, str] = {}
        for key, value in list(raw.items())[:20]:
            name = str(key or "").strip()
            cookie_value = str(value or "").strip()
            if not name or not cookie_value:
                continue
            cookies[name[:80]] = cookie_value[:512]
        return cookies

    def extract_auth_context_from_details(
        self, module_path: str, details: Any
    ) -> Optional[Dict[str, Any]]:
        if not isinstance(details, dict):
            return None

        username = str(details.get("authenticated_as") or details.get("username") or "").strip()
        password = str(details.get("password") or details.get("authenticated_password") or "").strip()
        login_path = self._normalize_relative_path(details.get("login_path") or details.get("path"))
        final_url = str(details.get("post_login_final_url") or "").strip()
        final_path = self._normalize_relative_path(
            details.get("post_login_final_path") or final_url
        )
        snippet = str(details.get("post_login_snippet") or "")[:12000]
        cookies = self.sanitize_cookie_map(
            details.get("session_cookies") or details.get("cookies")
        )

        if not any((username, password, login_path, final_url, final_path, snippet, cookies)):
            return None

        # A login URL alone is reconnaissance, not "credentials obtained". Treating it as auth
        # context incorrectly set risk_signals.credentials_obtained and halted the scan campaign
        # before bruteforce, XSS, PHP fingerprinting, etc.
        authenticated_as = str(details.get("authenticated_as") or "").strip()
        has_user_password = bool(username and password)
        has_identity = bool(authenticated_as)
        has_post_login_evidence = bool(snippet or final_url or final_path)
        has_session_material = bool(cookies) or bool(str(details.get("cookie_header") or "").strip())
        if (
            not has_user_password
            and not has_identity
            and not has_post_login_evidence
            and not has_session_material
        ):
            return None

        return {
            "source_module": str(module_path or "")[:200],
            "username": username,
            "password": password,
            "login_path": login_path,
            "final_url": final_url[:512],
            "final_path": final_path,
            "post_login_snippet": snippet,
            "cookies": cookies,
            "cookie_header": str(details.get("cookie_header") or "").strip()[:4000],
            "username_field": str(details.get("username_field") or "").strip()[:120],
            "password_field": str(details.get("password_field") or "").strip()[:120],
            "extra_fields": str(details.get("extra_fields") or "").strip()[:1024],
        }

    def score_auth_context(self, context: Optional[Dict[str, Any]]) -> int:
        if not isinstance(context, dict):
            return 0
        score = 0
        if context.get("username"):
            score += 2
        if context.get("password"):
            score += 2
        if context.get("login_path"):
            score += 1
        if context.get("final_path"):
            score += 1
        if context.get("post_login_snippet"):
            score += 1
        cookies = context.get("cookies") or {}
        if isinstance(cookies, dict) and cookies:
            score += 3
        if context.get("cookie_header"):
            score += 1
        return score

    def auth_context_signature(self, context: Optional[Dict[str, Any]]) -> str:
        if not isinstance(context, dict):
            return ""
        return "|".join([
            str(context.get("username", "")).strip().lower(),
            str(context.get("password", "")).strip(),
            str(context.get("login_path", "")).strip().lower(),
            str(context.get("final_path", "")).strip().lower(),
        ])

    def merge_auth_context(self, knowledge_base: Any, candidate: Optional[Dict[str, Any]]) -> None:
        if not isinstance(knowledge_base, dict) or not isinstance(candidate, dict):
            return

        existing_store = []
        for row in knowledge_base.get("credential_store", []) or []:
            if isinstance(row, dict):
                existing_store.append(dict(row))

        signature = self.auth_context_signature(candidate)
        merged = None
        for idx, row in enumerate(existing_store):
            if signature and self.auth_context_signature(row) == signature:
                merged = dict(row)
                merged.update({k: v for k, v in candidate.items() if v})
                existing_store[idx] = merged
                break

        if merged is None:
            existing_store.append(dict(candidate))
            merged = existing_store[-1]

        existing_store.sort(key=self.score_auth_context, reverse=True)
        knowledge_base["credential_store"] = existing_store[:6]

        current = knowledge_base.get("active_auth_context", {})
        if self.score_auth_context(merged) >= self.score_auth_context(current):
            knowledge_base["active_auth_context"] = merged

    def get_active_auth_context(self, knowledge_base: Any) -> Dict[str, Any]:
        kb = knowledge_base if isinstance(knowledge_base, dict) else {}
        active = kb.get("active_auth_context", {})
        if isinstance(active, dict) and active:
            return dict(active)
        for row in kb.get("credential_store", []) or []:
            if isinstance(row, dict) and row:
                return dict(row)
        return {}

    def _collect_login_path_candidates(self, knowledge_base: Any) -> List[str]:
        kb = knowledge_base if isinstance(knowledge_base, dict) else {}
        candidates: List[str] = []

        auth_context = self.get_active_auth_context(kb)
        for raw in (
            auth_context.get("login_path"),
            auth_context.get("final_path"),
        ):
            candidate = self._normalize_relative_path(raw)
            if candidate.startswith("/"):
                candidates.append(candidate.split("?", 1)[0])

        for raw in kb.get("login_paths", []):
            if isinstance(raw, str) and raw.startswith("/"):
                candidates.append(raw.split("?", 1)[0])

        for raw in kb.get("discovered_endpoints", []):
            if not isinstance(raw, str):
                continue
            candidate = raw.split("?", 1)[0]
            low = candidate.lower()
            if candidate.startswith("/") and any(token in low for token in AUTH_PATH_MARKERS):
                candidates.append(candidate)

        unique: List[str] = []
        seen = set()
        for candidate in candidates:
            normalized = str(candidate or "").strip()
            if not normalized or normalized in seen:
                continue
            unique.append(normalized)
            seen.add(normalized)
        return unique

    def _build_path_inference_context(self, knowledge_base: Any) -> Dict[str, Any]:
        kb = knowledge_base if isinstance(knowledge_base, dict) else {}
        auth_context = self.get_active_auth_context(kb)
        login_path = str(auth_context.get("login_path") or "").strip()
        if not login_path:
            login_path = self.select_best_login_path(kb)

        final_path = str(auth_context.get("final_path") or "").strip()
        if not final_path:
            milestone = kb.get("auth_milestone", {}) if isinstance(kb.get("auth_milestone", {}), dict) else {}
            final_path = self._normalize_relative_path(milestone.get("landing_path"))

        return {
            "username": str(auth_context.get("username") or "").strip(),
            "password": str(auth_context.get("password") or "").strip(),
            "login_path": login_path,
            "final_path": final_path,
            "session_cookie": self.extract_preferred_session_cookie(auth_context),
            "auth_context": auth_context,
            "login_candidates": self._collect_login_path_candidates(kb),
        }

    def extract_preferred_session_cookie(self, auth_context: Optional[Dict[str, Any]]) -> str:
        if not isinstance(auth_context, dict):
            return ""
        cookies = auth_context.get("cookies") or {}
        if isinstance(cookies, dict):
            for name, value in cookies.items():
                low = str(name).lower()
                if any(marker in low for marker in SESSION_COOKIE_NAME_MARKERS):
                    return str(value)
            for _, value in cookies.items():
                if value:
                    return str(value)
        return str(auth_context.get("cookie_header") or "").strip()

    def seed_http_session_from_auth(
        self, module_instance: Any, state: AgentState, auth_context: Any = None
    ) -> None:
        context = auth_context if isinstance(auth_context, dict) else self.get_active_auth_context(
            state.knowledge_base
        )
        if not context:
            return
        cookies = context.get("cookies") or {}
        if isinstance(cookies, dict) and cookies and hasattr(module_instance, "set_cookie"):
            for name, value in cookies.items():
                try:
                    module_instance.set_cookie(str(name), str(value))
                except Exception:
                    continue
        cookie_header = str(context.get("cookie_header") or "").strip()
        if cookie_header and hasattr(module_instance, "set_header"):
            try:
                module_instance.set_header("Cookie", cookie_header)
            except Exception:
                pass

    def infer_auth_option_overrides(
        self, module_instance: Any, module_path: str, state: AgentState
    ) -> Dict[str, Any]:
        inference_context = self._build_path_inference_context(state.knowledge_base)
        auth_context = inference_context.get("auth_context") or {}
        login_path = str(inference_context.get("login_path") or "").strip()
        final_path = str(inference_context.get("final_path") or "").strip()
        session_cookie = str(inference_context.get("session_cookie") or "").strip()
        username = str(inference_context.get("username") or "").strip()
        password = str(inference_context.get("password") or "").strip()

        if not any((auth_context, login_path, final_path, session_cookie, username, password)):
            return {}
        ctx = AuthOverrideBuildContext(
            module_instance=module_instance,
            module_path=str(module_path or ""),
            auth_context=auth_context,
            username=username,
            password=password,
            login_path=login_path,
            final_path=final_path,
            session_cookie=session_cookie,
        )
        return compose_auth_option_overrides(ctx)

    def select_best_login_path(self, knowledge_base: Any) -> str:
        kb = knowledge_base if isinstance(knowledge_base, dict) else {}
        auth_context = self.get_active_auth_context(kb)
        auth_login_path = str(auth_context.get("login_path") or "").strip()
        if auth_login_path.startswith("/"):
            return auth_login_path
        candidates = self._collect_login_path_candidates(kb)
        if not candidates:
            return ""

        # Prefer scoped app paths over root-level aliases when both exist
        # (e.g. "/dvwa/login.php" should beat "/login.php").
        for preferred in LOGIN_PATH_PRIORITY:
            scoped = [
                candidate for candidate in candidates
                if candidate != preferred and candidate.lower().endswith(preferred.lower())
            ]
            if scoped:
                return sorted(scoped, key=lambda value: (len(value), value))[0]
        for preferred in LOGIN_PATH_PRIORITY:
            for candidate in candidates:
                if candidate.lower() == preferred:
                    return candidate
        non_root = [c for c in set(candidates) if c not in ("/", "")]
        if non_root:
            return sorted(non_root, key=lambda value: (len(value), value))[0]
        return sorted(set(candidates), key=lambda value: (len(value), value))[0]

    def build_inferred_option_overrides(self, modules: Any, state: AgentState) -> Dict[str, Any]:
        kb = state.knowledge_base
        login_path = self.select_best_login_path(kb)
        if not login_path:
            return {}
        overrides: Dict[str, Dict[str, Any]] = {}
        bf_extras = infer_bruteforce_field_overrides(login_path)
        for module in modules or []:
            path = str(module.get("path", "")).strip()
            if not path:
                continue
            if path == "auxiliary/scanner/http/login_page_detector":
                overrides[path] = {
                    "custom_paths": login_path,
                    "max_paths": 8,
                }
            elif path == "auxiliary/scanner/http/login/admin_login_bruteforce":
                overrides[path] = {
                    "path": login_path,
                    "max_attempts": 10,
                    **bf_extras,
                }
        return overrides
