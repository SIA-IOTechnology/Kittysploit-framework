#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Shared API/MCP security helpers: rotating tokens and role permissions."""

from __future__ import annotations

import hmac
import hashlib
import os
import secrets
import threading
import time
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple


VIEWER_PERMISSIONS = {
    "health:read",
    "openapi:read",
    "metrics:read",
    "modules:read",
    "sessions:read",
    "output:read",
    "events:read",
    "resources:read",
    "workspaces:read",
    "registry:read",
    "mcp:read",
}

OPERATOR_PERMISSIONS = VIEWER_PERMISSIONS | {
    "modules:run",
    "sessions:delete",
    "pipelines:write",
    "workspaces:switch",
    "commands:execute",
    "mcp:execute",
}

ADMIN_PERMISSIONS = {"*"}

ROLE_PERMISSIONS = {
    "viewer": VIEWER_PERMISSIONS,
    "operator": OPERATOR_PERMISSIONS,
    "admin": ADMIN_PERMISSIONS,
}

DEFAULT_ACCESS_TTL_SECONDS = 15 * 60
DEFAULT_REFRESH_TTL_SECONDS = 24 * 60 * 60

DEFAULT_RATE_LIMIT_TIERS: Dict[str, Tuple[int, int]] = {
    "public": (300, 60),
    "auth": (20, 60),
    "read": (120, 60),
    "mutate": (40, 60),
    "admin": (15, 60),
}


@dataclass(frozen=True)
class AuthContext:
    """Authenticated principal and its resolved permissions."""

    subject: str
    roles: Tuple[str, ...]
    permissions: frozenset[str]
    source: str
    token_id: Optional[str] = None
    token_kind: Optional[str] = None
    expires_at: Optional[float] = None
    bootstrap: bool = False

    def has_permission(self, permission: Optional[str]) -> bool:
        if not permission or permission == "authenticated":
            return True
        return "*" in self.permissions or permission in self.permissions

    def to_dict(self, include_permissions: bool = True) -> Dict[str, Any]:
        data: Dict[str, Any] = {
            "subject": self.subject,
            "roles": list(self.roles),
            "source": self.source,
            "token_id": self.token_id,
            "token_kind": self.token_kind,
            "bootstrap": self.bootstrap,
            "expires_at": iso_timestamp(self.expires_at) if self.expires_at else None,
        }
        if include_permissions:
            data["permissions"] = sorted(self.permissions)
        return data


@dataclass
class _TokenRecord:
    token_id: str
    secret_hash: str
    subject: str
    roles: Tuple[str, ...]
    permissions: frozenset[str]
    kind: str
    issued_at: float
    expires_at: float
    family_id: str
    revoked: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)


def iso_timestamp(value: Optional[float] = None) -> str:
    """Return a compact UTC timestamp without adding a hard dependency."""
    import datetime as _dt

    ts = time.time() if value is None else value
    return (
        _dt.datetime.fromtimestamp(ts, _dt.timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def normalize_roles(roles: Optional[Iterable[str]]) -> Tuple[str, ...]:
    normalized = []
    for role in roles or ("viewer",):
        r = str(role).strip().lower()
        if r and r in ROLE_PERMISSIONS and r not in normalized:
            normalized.append(r)
    return tuple(normalized or ["viewer"])


def permissions_for_roles(
    roles: Optional[Iterable[str]],
    extra_permissions: Optional[Iterable[str]] = None,
) -> frozenset[str]:
    resolved: Set[str] = set()
    for role in normalize_roles(roles):
        perms = ROLE_PERMISSIONS.get(role, set())
        if "*" in perms:
            resolved.add("*")
        else:
            resolved.update(perms)
    for permission in extra_permissions or ():
        p = str(permission).strip()
        if p:
            resolved.add(p)
    return frozenset(resolved)


def parse_roles_env(name: str, default: Sequence[str]) -> Tuple[str, ...]:
    raw = os.environ.get(name, "")
    if not raw.strip():
        return normalize_roles(default)
    return normalize_roles(part.strip() for part in raw.split(","))


def mask_token(token: Optional[str]) -> str:
    if not token:
        return ""
    token = str(token)
    if len(token) <= 12:
        return "***"
    return f"{token[:6]}...{token[-4:]}"


def secrets_equal(left: Optional[str], right: Optional[str]) -> bool:
    """Constant-time comparison for API keys and other shared secrets."""
    a = (left or "").strip()
    b = (right or "").strip()
    if not a or not b:
        return False
    return hmac.compare_digest(a, b)


def parse_cors_origins(raw: Optional[str]) -> Optional[list[str]]:
    """
    Parse KITTYSPLOIT_API_CORS_ORIGINS.

    Returns None when CORS should stay disabled, ["*"] for explicit wildcard.
    """
    value = (raw or "").strip()
    if not value:
        return None
    if value == "*":
        return ["*"]
    origins = [origin.strip() for origin in value.split(",") if origin.strip()]
    return origins or None


class ApiRateLimiter:
    """Simple per-client sliding-window rate limiter for HTTP API routes."""

    def __init__(
        self,
        tiers: Optional[Dict[str, Tuple[int, int]]] = None,
    ) -> None:
        self.tiers = dict(tiers or DEFAULT_RATE_LIMIT_TIERS)
        self._buckets: Dict[str, list[float]] = {}
        self._lock = threading.RLock()

    def allow(self, tier: str, client_key: str) -> Tuple[bool, Optional[Dict[str, int]]]:
        fallback = DEFAULT_RATE_LIMIT_TIERS["read"]
        max_requests, window_sec = self.tiers.get(tier, fallback)
        if max_requests <= 0:
            return True, None

        now = time.time()
        bucket_key = f"{tier}:{client_key}"
        with self._lock:
            hits = [ts for ts in self._buckets.get(bucket_key, []) if now - ts < window_sec]
            if len(hits) >= max_requests:
                retry_after = max(1, int(window_sec - (now - hits[0])))
                return False, {
                    "retry_after": retry_after,
                    "limit": max_requests,
                    "window_seconds": window_sec,
                }
            hits.append(now)
            self._buckets[bucket_key] = hits
        return True, None


class RotatingTokenManager:
    """In-memory access/refresh token store with refresh-token rotation."""

    def __init__(
        self,
        bootstrap_secret: Optional[str],
        *,
        issuer: str = "kittysploit",
        access_ttl_seconds: Optional[int] = None,
        refresh_ttl_seconds: Optional[int] = None,
        bootstrap_expiry_seconds: Optional[int] = None,
    ) -> None:
        self.bootstrap_secret = (bootstrap_secret or "").strip() or None
        self.issuer = issuer
        self.access_ttl_seconds = int(
            access_ttl_seconds
            or os.environ.get("KITTYSPLOIT_ACCESS_TOKEN_TTL", DEFAULT_ACCESS_TTL_SECONDS)
        )
        self.refresh_ttl_seconds = int(
            refresh_ttl_seconds
            or os.environ.get("KITTYSPLOIT_REFRESH_TOKEN_TTL", DEFAULT_REFRESH_TTL_SECONDS)
        )
        self._bootstrap_expiry_seconds = int(
            bootstrap_expiry_seconds
            or os.environ.get("KITTYSPLOIT_BOOTSTRAP_TTL", 3600)
        )
        self._records: Dict[str, _TokenRecord] = {}
        self._lock = threading.RLock()
        self._token_hmac_key: bytes = secrets.token_bytes(32)
        self._bootstrap_enabled: bool = bool(self.bootstrap_secret)

    def bootstrap_context(self) -> Optional[AuthContext]:
        if not self.bootstrap_secret or not self._bootstrap_enabled:
            return None
        return AuthContext(
            subject="bootstrap",
            roles=("admin",),
            permissions=frozenset({"*"}),
            source="api_key",
            token_kind="bootstrap",
            bootstrap=True,
            expires_at=time.time() + self._bootstrap_expiry_seconds,
        )

    def disable_bootstrap(self) -> None:
        self._bootstrap_enabled = False

    @property
    def bootstrap_enabled(self) -> bool:
        return self._bootstrap_enabled

    def authenticate(self, token: Optional[str], *, expected_kind: str = "access") -> Optional[AuthContext]:
        token = (token or "").strip()
        if not token:
            return None

        if self._bootstrap_enabled and self.bootstrap_secret and secrets_equal(token, self.bootstrap_secret):
            return self.bootstrap_context()

        parsed = self._parse_token(token)
        if not parsed:
            return None
        token_id, secret = parsed

        with self._lock:
            record = self._records.get(token_id)
            if not record or record.revoked or record.kind != expected_kind:
                return None
            if record.expires_at <= time.time():
                record.revoked = True
                return None
            if not hmac.compare_digest(record.secret_hash, self._hash_secret(secret)):
                return None
            if self._bootstrap_enabled:
                self._bootstrap_enabled = False
            return AuthContext(
                subject=record.subject,
                roles=record.roles,
                permissions=record.permissions,
                source="rotating_token",
                token_id=record.token_id,
                token_kind=record.kind,
                expires_at=record.expires_at,
            )

    def issue_pair(
        self,
        *,
        subject: str = "operator",
        roles: Optional[Iterable[str]] = None,
        permissions: Optional[Iterable[str]] = None,
        access_ttl_seconds: Optional[int] = None,
        refresh_ttl_seconds: Optional[int] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        resolved_roles = normalize_roles(roles or ("operator",))
        resolved_permissions = permissions_for_roles(resolved_roles, permissions)
        now = time.time()
        family_id = secrets.token_urlsafe(12)
        access_ttl = max(30, int(access_ttl_seconds or self.access_ttl_seconds))
        refresh_ttl = max(access_ttl, int(refresh_ttl_seconds or self.refresh_ttl_seconds))

        access_token, access_record = self._new_record(
            subject=subject,
            roles=resolved_roles,
            permissions=resolved_permissions,
            kind="access",
            issued_at=now,
            expires_at=now + access_ttl,
            family_id=family_id,
            metadata=metadata or {},
        )
        refresh_token, refresh_record = self._new_record(
            subject=subject,
            roles=resolved_roles,
            permissions=resolved_permissions,
            kind="refresh",
            issued_at=now,
            expires_at=now + refresh_ttl,
            family_id=family_id,
            metadata=metadata or {},
        )

        with self._lock:
            self._records[access_record.token_id] = access_record
            self._records[refresh_record.token_id] = refresh_record
            self._cleanup_expired_locked()

        return {
            "token_type": "Bearer",
            "access_token": access_token,
            "refresh_token": refresh_token,
            "expires_in": access_ttl,
            "expires_at": iso_timestamp(access_record.expires_at),
            "refresh_expires_at": iso_timestamp(refresh_record.expires_at),
            "subject": subject,
            "roles": list(resolved_roles),
            "permissions": sorted(resolved_permissions),
        }

    def rotate_refresh(self, refresh_token: Optional[str]) -> Optional[Dict[str, Any]]:
        refresh_token = (refresh_token or "").strip()
        parsed = self._parse_token(refresh_token)
        if not parsed:
            return None
        token_id, secret = parsed

        with self._lock:
            record = self._records.get(token_id)
            if (
                not record
                or record.revoked
                or record.kind != "refresh"
                or record.expires_at <= time.time()
                or not hmac.compare_digest(record.secret_hash, self._hash_secret(secret))
            ):
                if record:
                    record.revoked = True
                return None
            subject = record.subject
            roles = record.roles
            permissions = record.permissions
            metadata = dict(record.metadata)
            family_id = record.family_id
            for existing in self._records.values():
                if existing.family_id == family_id:
                    existing.revoked = True

        return self.issue_pair(
            subject=subject,
            roles=roles,
            permissions=permissions,
            metadata=metadata,
        )

    def revoke(self, token: Optional[str]) -> bool:
        parsed = self._parse_token(token or "")
        if not parsed:
            return False
        token_id, _secret = parsed
        with self._lock:
            record = self._records.get(token_id)
            if not record:
                return False
            record.revoked = True
            return True

    def stats(self) -> Dict[str, Any]:
        with self._lock:
            self._cleanup_expired_locked()
            active_access = sum(1 for r in self._records.values() if r.kind == "access" and not r.revoked)
            active_refresh = sum(1 for r in self._records.values() if r.kind == "refresh" and not r.revoked)
            revoked = sum(1 for r in self._records.values() if r.revoked)
        return {
            "bootstrap_configured": bool(self.bootstrap_secret),
            "bootstrap_enabled": self._bootstrap_enabled,
            "rotation_enabled": True,
            "access_ttl_seconds": self.access_ttl_seconds,
            "refresh_ttl_seconds": self.refresh_ttl_seconds,
            "active_access_tokens": active_access,
            "active_refresh_tokens": active_refresh,
            "revoked_tokens": revoked,
            "roles": sorted(ROLE_PERMISSIONS.keys()),
        }

    def _new_record(
        self,
        *,
        subject: str,
        roles: Tuple[str, ...],
        permissions: frozenset[str],
        kind: str,
        issued_at: float,
        expires_at: float,
        family_id: str,
        metadata: Dict[str, Any],
    ) -> Tuple[str, _TokenRecord]:
        token_id = secrets.token_urlsafe(12)
        secret = secrets.token_urlsafe(32)
        token = f"kst_{token_id}.{secret}"
        record = _TokenRecord(
            token_id=token_id,
            secret_hash=self._hash_secret(secret),
            subject=subject,
            roles=roles,
            permissions=permissions,
            kind=kind,
            issued_at=issued_at,
            expires_at=expires_at,
            family_id=family_id,
            metadata=metadata,
        )
        return token, record

    def _parse_token(self, token: str) -> Optional[Tuple[str, str]]:
        token = (token or "").strip()
        if not token.startswith("kst_") or "." not in token:
            return None
        token_body = token[4:]
        token_id, secret = token_body.split(".", 1)
        if not token_id or not secret:
            return None
        return token_id, secret

    def _hash_secret(self, secret: str) -> str:
        return hmac.new(self._token_hmac_key, secret.encode("utf-8"), hashlib.sha256).hexdigest()

    def _cleanup_expired_locked(self) -> None:
        now = time.time()
        for record in self._records.values():
            if record.expires_at <= now:
                record.revoked = True


class RequestAuthenticator:
    """Extract credentials from Flask-like request objects and enforce permissions."""

    def __init__(self, token_manager: RotatingTokenManager) -> None:
        self.token_manager = token_manager

    def authenticate_request(
        self,
        req: Any,
        required_permission: Optional[str] = None,
    ) -> Tuple[Optional[AuthContext], Optional[Dict[str, Any]]]:
        token = self._extract_request_token(req)
        ctx = self.token_manager.authenticate(token, expected_kind="access")
        if not ctx:
            return None, {
                "status_code": 401,
                "error": "Unauthorized",
                "message": "A valid API key or Bearer access token is required.",
            }
        if not ctx.has_permission(required_permission):
            return None, {
                "status_code": 403,
                "error": "Forbidden",
                "message": "The authenticated principal lacks the required permission.",
                "required_permission": required_permission,
                "roles": list(ctx.roles),
            }
        return ctx, None

    def _extract_request_token(self, req: Any) -> Optional[str]:
        api_key = req.headers.get("X-API-Key") if hasattr(req, "headers") else None
        if api_key:
            return api_key.strip()
        auth_header = req.headers.get("Authorization") if hasattr(req, "headers") else None
        if auth_header:
            auth_header = auth_header.strip()
            if auth_header.lower().startswith("bearer "):
                return auth_header[7:].strip()
            return auth_header
        return None


@dataclass(frozen=True)
class MCPToolScope:
    """RBAC permission and consent requirements for one MCP tool."""

    permission: str
    dangerous: bool = False
    param_consent: Optional[str] = None


MCP_TOOL_SCOPES: Dict[str, MCPToolScope] = {
    "ks_health": MCPToolScope("health:read"),
    "ks_security_context": MCPToolScope("mcp:read"),
    "ks_framework_state": MCPToolScope("mcp:read"),
    "ks_ollama_status": MCPToolScope("mcp:read"),
    "ks_list_modules": MCPToolScope("modules:read"),
    "ks_get_module_info": MCPToolScope("modules:read"),
    "ks_get_module_options": MCPToolScope("modules:read"),
    "ks_prepare_module_run": MCPToolScope("modules:read"),
    "ks_run_module": MCPToolScope("modules:run", dangerous=True),
    "ks_get_module_logs": MCPToolScope("output:read"),
    "ks_execute_interpreter": MCPToolScope("interpreter:execute", dangerous=True),
    "ks_list_commands": MCPToolScope("mcp:read"),
    "ks_get_command_help": MCPToolScope("mcp:read"),
    "ks_execute_command": MCPToolScope("commands:execute", param_consent="allow_dangerous"),
    "ks_plan_natural_request": MCPToolScope("mcp:read"),
    "ks_run_agent": MCPToolScope("mcp:execute", dangerous=True, param_consent="allow_dangerous"),
    "ks_execute_natural_request": MCPToolScope("mcp:execute", param_consent="allow_dangerous"),
    "ks_list_workspaces": MCPToolScope("workspaces:read"),
    "ks_switch_workspace": MCPToolScope("workspaces:switch"),
    "ks_mcp_audit": MCPToolScope("mcp:read"),
}


def mcp_dangerous_consent_enabled(explicit: Optional[bool] = None) -> bool:
    """Return True when the MCP server was started with explicit dangerous-action consent."""
    if explicit is not None:
        return explicit
    return os.environ.get("KITTYMCP_DANGEROUS_CONSENT", "").strip().lower() in (
        "1",
        "true",
        "yes",
        "on",
    )


class MCPExecutionJournal:
    """Append-only audit log for MCP tool invocations (local stdio / HTTP transports)."""

    def __init__(self, audit_path: Optional[Path] = None) -> None:
        if audit_path is not None:
            self._audit_path = audit_path
        else:
            base = Path(os.environ.get("KITTYMCP_AUDIT_DIR", os.path.expanduser("~/.kittysploit/mcp")))
            self._audit_path = base / "audit.jsonl"
        self._audit_path.parent.mkdir(parents=True, exist_ok=True)

    @property
    def audit_path(self) -> Path:
        return self._audit_path

    def record(
        self,
        *,
        tool: str,
        permission: str,
        status: str,
        subject: str,
        roles: Sequence[str],
        allow_dangerous: bool = False,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        record = {
            "timestamp": iso_timestamp(),
            "tool": tool,
            "permission": permission,
            "status": status,
            "subject": subject,
            "roles": list(roles),
            "allow_dangerous": allow_dangerous,
            "details": details or {},
        }
        try:
            with open(self._audit_path, "a", encoding="utf-8") as handle:
                handle.write(json.dumps(record, ensure_ascii=False) + "\n")
        except OSError as exc:
            import logging

            logging.getLogger(__name__).warning("MCP audit write failed: %s", exc)

    def read(self, limit: int = 50) -> List[Dict[str, Any]]:
        if not self._audit_path.is_file():
            return []
        lines = self._audit_path.read_text(encoding="utf-8").splitlines()
        records: List[Dict[str, Any]] = []
        for line in lines[-max(1, limit) :]:
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return records


class MCPAuthorizer:
    """Process-wide MCP permission guard for stdio and HTTP transports."""

    def __init__(
        self,
        roles: Optional[Iterable[str]] = None,
        permissions: Optional[Iterable[str]] = None,
        *,
        dangerous_consent: Optional[bool] = None,
        journal: Optional[MCPExecutionJournal] = None,
    ) -> None:
        resolved_roles = normalize_roles(roles or parse_roles_env("KITTYMCP_ROLES", ("operator",)))
        self.context = AuthContext(
            subject=os.environ.get("KITTYMCP_SUBJECT", "mcp-local"),
            roles=resolved_roles,
            permissions=permissions_for_roles(resolved_roles, permissions),
            source="mcp_server_config",
            token_kind="mcp",
        )
        self.dangerous_consent = mcp_dangerous_consent_enabled(dangerous_consent)
        self.journal = journal or MCPExecutionJournal()

    def require(self, permission: Optional[str]) -> Optional[Dict[str, Any]]:
        if self.context.has_permission(permission):
            return None
        return {
            "error": "forbidden",
            "message": "MCP tool blocked by RBAC policy.",
            "required_permission": permission,
            "security_context": self.context.to_dict(),
        }

    def _needs_dangerous_consent(self, scope: MCPToolScope, kwargs: Dict[str, Any]) -> bool:
        if scope.dangerous:
            return True
        if scope.param_consent and kwargs.get(scope.param_consent):
            return True
        return False

    def authorize_tool(self, tool_name: str, **kwargs: Any) -> Optional[Dict[str, Any]]:
        """Check RBAC scope and explicit dangerous-action consent for an MCP tool."""
        scope = MCP_TOOL_SCOPES.get(tool_name)
        if scope is None:
            return {
                "error": "unknown_tool",
                "message": f"No security scope registered for MCP tool {tool_name!r}.",
            }

        allow_dangerous = bool(kwargs.get("allow_dangerous", False))
        blocked = self.require(scope.permission)
        if blocked:
            self.journal.record(
                tool=tool_name,
                permission=scope.permission,
                status="forbidden",
                subject=self.context.subject,
                roles=self.context.roles,
                allow_dangerous=allow_dangerous,
            )
            return blocked

        if self._needs_dangerous_consent(scope, kwargs) and not self.dangerous_consent:
            result = {
                "error": "dangerous_consent_required",
                "message": (
                    "This MCP tool can run scanners, exploits, listeners, or arbitrary code. "
                    "Start the server with --dangerous-consent or set KITTYMCP_DANGEROUS_CONSENT=1."
                ),
                "tool": tool_name,
                "required_permission": scope.permission,
                "security_context": self.to_dict(),
            }
            self.journal.record(
                tool=tool_name,
                permission=scope.permission,
                status="consent_required",
                subject=self.context.subject,
                roles=self.context.roles,
                allow_dangerous=allow_dangerous,
            )
            return result

        return None

    def log_tool_result(
        self,
        tool_name: str,
        result: Any,
        *,
        allow_dangerous: bool = False,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        scope = MCP_TOOL_SCOPES.get(tool_name)
        permission = scope.permission if scope else "unknown"
        status = "ok"
        if isinstance(result, dict):
            if result.get("error") in ("forbidden", "dangerous_consent_required"):
                status = "blocked"
            elif result.get("status") in ("requires_allow_dangerous", "blocked", "consent_required"):
                status = "blocked"
            elif "error" in result:
                status = "error"
        self.journal.record(
            tool=tool_name,
            permission=permission,
            status=status,
            subject=self.context.subject,
            roles=self.context.roles,
            allow_dangerous=allow_dangerous,
            details=details,
        )

    def to_dict(self) -> Dict[str, Any]:
        data = self.context.to_dict()
        data["dangerous_consent"] = self.dangerous_consent
        data["audit_path"] = str(self.journal.audit_path)
        data["tool_scopes"] = {
            name: {
                "permission": scope.permission,
                "dangerous": scope.dangerous,
                "param_consent": scope.param_consent,
            }
            for name, scope in sorted(MCP_TOOL_SCOPES.items())
        }
        return data
