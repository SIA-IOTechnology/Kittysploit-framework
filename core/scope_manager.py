#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Engagement scope enforcement: allowlist, rate limits, confirmations, audit."""

from __future__ import annotations

import json
import logging
import os
import re
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Set
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

try:
    import netaddr
except ImportError:
    netaddr = None  # type: ignore

TARGET_OPTION_NAMES = (
    "target",
    "rhost",
    "rhosts",
    "host",
    "hostname",
    "ip",
    "url",
    "targeturi",
    "domain",
    "vhost",
    "RHOST",
    "RHOSTS",
    "HOST",
)

DESTRUCTIVE_PATH_KEYWORDS = (
    "dos",
    "wipe",
    "destroy",
    "delete",
    "format",
    "ransom",
    "brick",
    "shutdown",
    "fork_bomb",
)

IPV4_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}"
    r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
)


@dataclass
class ScopeDecision:
    allowed: bool
    action: str  # allow, deny, confirm_required, rate_limited, not_enforced
    reason: str
    targets: List[str] = field(default_factory=list)
    details: List[str] = field(default_factory=list)


class ScopeManager:
    """Proactive engagement scope separate from Guardian behavioral analysis."""

    def __init__(self, workspace: str = "default", config_dir: Optional[str] = None):
        self.workspace = workspace
        base = Path(config_dir or os.path.expanduser("~/.kittysploit/scope"))
        base.mkdir(parents=True, exist_ok=True)
        self.config_dir = base
        self._config_path = base / f"{workspace}.json"
        self._audit_path = base / f"{workspace}.audit.jsonl"

        self.enabled = False
        self.allowed_ips: List[str] = []
        self.allowed_domains: List[str] = []
        self.rate_limit_max = 0
        self.rate_limit_window_sec = 60
        self.require_confirm_destructive = True

        self._rate_buckets: Dict[str, List[float]] = {}
        self.last_decision: Optional[ScopeDecision] = None
        self.load()

    def _now_iso(self) -> str:
        return datetime.now(timezone.utc).isoformat()

    def config_path(self) -> Path:
        return self._config_path

    def audit_path(self) -> Path:
        return self._audit_path

    def set_workspace(self, workspace: str) -> None:
        self.workspace = workspace
        self._config_path = self.config_dir / f"{workspace}.json"
        self._audit_path = self.config_dir / f"{workspace}.audit.jsonl"
        self._rate_buckets = {}
        self.load()

    def load(self) -> None:
        if not self._config_path.is_file():
            return
        try:
            with open(self._config_path, "r", encoding="utf-8") as handle:
                data = json.load(handle) or {}
            self.enabled = bool(data.get("enabled", False))
            self.allowed_ips = list(data.get("allowed_ips") or [])
            self.allowed_domains = [d.lower() for d in (data.get("allowed_domains") or [])]
            self.rate_limit_max = int(data.get("rate_limit_max") or 0)
            self.rate_limit_window_sec = max(1, int(data.get("rate_limit_window_sec") or 60))
            self.require_confirm_destructive = bool(data.get("require_confirm_destructive", True))
        except Exception as exc:
            logger.warning("Could not load scope config for %s: %s", self.workspace, exc)

    def save(self) -> None:
        payload = {
            "workspace": self.workspace,
            "enabled": self.enabled,
            "allowed_ips": self.allowed_ips,
            "allowed_domains": self.allowed_domains,
            "rate_limit_max": self.rate_limit_max,
            "rate_limit_window_sec": self.rate_limit_window_sec,
            "require_confirm_destructive": self.require_confirm_destructive,
            "updated_at": self._now_iso(),
        }
        with open(self._config_path, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2)

    def enable(self) -> None:
        self.enabled = True
        self.save()
        self.audit("scope_enabled", {"workspace": self.workspace})

    def disable(self) -> None:
        self.enabled = False
        self.save()
        self.audit("scope_disabled", {"workspace": self.workspace})

    def add_allow_ip(self, entry: str) -> None:
        normalized = entry.strip()
        if not normalized:
            raise ValueError("Empty IP/CIDR entry")
        if netaddr is not None:
            netaddr.IPNetwork(normalized)
        if normalized not in self.allowed_ips:
            self.allowed_ips.append(normalized)
            self.save()
            self.audit("allow_ip_added", {"entry": normalized})

    def remove_allow_ip(self, entry: str) -> bool:
        normalized = entry.strip()
        if normalized in self.allowed_ips:
            self.allowed_ips.remove(normalized)
            self.save()
            self.audit("allow_ip_removed", {"entry": normalized})
            return True
        return False

    def add_allow_domain(self, entry: str) -> None:
        normalized = self._normalize_domain(entry)
        if not normalized:
            raise ValueError("Empty domain entry")
        if normalized not in self.allowed_domains:
            self.allowed_domains.append(normalized)
            self.save()
            self.audit("allow_domain_added", {"entry": normalized})

    def remove_allow_domain(self, entry: str) -> bool:
        normalized = self._normalize_domain(entry)
        if normalized in self.allowed_domains:
            self.allowed_domains.remove(normalized)
            self.save()
            self.audit("allow_domain_removed", {"entry": normalized})
            return True
        return False

    def set_rate_limit(self, max_actions: int, window_sec: int = 60) -> None:
        self.rate_limit_max = max(0, int(max_actions))
        self.rate_limit_window_sec = max(1, int(window_sec))
        self.save()
        self.audit(
            "rate_limit_updated",
            {"max": self.rate_limit_max, "window_sec": self.rate_limit_window_sec},
        )

    def status_dict(self) -> Dict[str, Any]:
        return {
            "workspace": self.workspace,
            "enabled": self.enabled,
            "allowed_ips": list(self.allowed_ips),
            "allowed_domains": list(self.allowed_domains),
            "rate_limit_max": self.rate_limit_max,
            "rate_limit_window_sec": self.rate_limit_window_sec,
            "require_confirm_destructive": self.require_confirm_destructive,
            "config_path": str(self._config_path),
            "audit_path": str(self._audit_path),
        }

    def audit(self, event: str, payload: Optional[Dict[str, Any]] = None) -> None:
        record = {
            "timestamp": self._now_iso(),
            "workspace": self.workspace,
            "event": event,
            "payload": payload or {},
        }
        try:
            with open(self._audit_path, "a", encoding="utf-8") as handle:
                handle.write(json.dumps(record, ensure_ascii=False) + "\n")
        except Exception as exc:
            logger.warning("Scope audit write failed: %s", exc)

    def read_audit(self, limit: int = 20) -> List[Dict[str, Any]]:
        if not self._audit_path.is_file():
            return []
        lines = self._audit_path.read_text(encoding="utf-8").splitlines()
        records: List[Dict[str, Any]] = []
        for line in lines[-limit:]:
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return records

    def _normalize_domain(self, value: str) -> str:
        text = value.strip().lower()
        if text.startswith("*."):
            return text
        if text.startswith("."):
            return "*" + text
        return text

    def _hostname_from_value(self, value: str) -> Optional[str]:
        text = value.strip()
        if not text:
            return None
        if "://" in text or text.startswith("http"):
            try:
                parsed = urlparse(text if "://" in text else f"http://{text}")
                return (parsed.hostname or "").lower() or None
            except Exception:
                return None
        if "/" in text and "." in text.split("/")[0]:
            return text.split("/")[0].lower()
        if re.match(r"^[a-z0-9][a-z0-9.-]*\.[a-z]{2,}$", text, re.I):
            return text.lower()
        return None

    def extract_targets_from_module(self, module) -> List[str]:
        targets: Set[str] = set()
        for attr_name in TARGET_OPTION_NAMES:
            if not hasattr(module, attr_name):
                continue
            try:
                value = getattr(module, attr_name)
                option_descriptor = getattr(type(module), attr_name, None)
                if option_descriptor and hasattr(option_descriptor, "_instance_values"):
                    instance_id = id(module)
                    stored = option_descriptor._instance_values.get(instance_id)
                    if stored:
                        value = stored.get("value") or stored.get("display_value") or value
                if value is None:
                    continue
                for token in self._tokenize_target_value(str(value)):
                    if token:
                        targets.add(token)
            except Exception:
                continue
        return sorted(targets)

    def _tokenize_target_value(self, value: str) -> List[str]:
        text = value.strip()
        if not text or text.lower() in {"none", "null"}:
            return []
        parts = re.split(r"[\s,;]+", text)
        tokens: List[str] = []
        for part in parts:
            part = part.strip()
            if not part:
                continue
            ip_match = IPV4_RE.search(part)
            if ip_match:
                tokens.append(ip_match.group(0))
            host = self._hostname_from_value(part)
            if host:
                tokens.append(host)
            elif IPV4_RE.fullmatch(part):
                tokens.append(part)
        return tokens

    def _target_kind(self, target: str) -> str:
        if IPV4_RE.fullmatch(target):
            return "ip"
        return "domain"

    def is_target_allowed(self, target: str) -> ScopeDecision:
        if not self.enabled:
            return ScopeDecision(True, "not_enforced", "Scope enforcement disabled", [target])

        if not self.allowed_ips and not self.allowed_domains:
            return ScopeDecision(
                False,
                "deny",
                "Scope enabled but allowlist is empty",
                [target],
                ["Add targets with: scope allow ip|domain <entry>"],
            )

        kind = self._target_kind(target)
        if kind == "ip":
            if self._ip_allowed(target):
                return ScopeDecision(True, "allow", f"IP {target} is in scope", [target])
            return ScopeDecision(
                False,
                "deny",
                f"IP {target} is outside engagement scope",
                [target],
            )

        if self._domain_allowed(target):
            return ScopeDecision(True, "allow", f"Domain {target} is in scope", [target])
        return ScopeDecision(
            False,
            "deny",
            f"Domain {target} is outside engagement scope",
            [target],
        )

    def _ip_allowed(self, ip: str) -> bool:
        if netaddr is None:
            return ip in self.allowed_ips
        try:
            address = netaddr.IPAddress(ip)
            for entry in self.allowed_ips:
                try:
                    network = netaddr.IPNetwork(entry)
                    if address in network:
                        return True
                except (netaddr.AddrFormatError, ValueError):
                    if entry == ip:
                        return True
        except (netaddr.AddrFormatError, ValueError):
            return ip in self.allowed_ips
        return False

    def _domain_allowed(self, host: str) -> bool:
        host = host.lower().strip(".")
        for pattern in self.allowed_domains:
            if pattern.startswith("*."):
                suffix = pattern[2:]
                if host == suffix or host.endswith("." + suffix):
                    return True
            elif host == pattern:
                return True
        return False

    def _check_rate_limit(self, targets: Sequence[str]) -> Optional[ScopeDecision]:
        if self.rate_limit_max <= 0 or not targets:
            return None
        now = time.time()
        bucket_key = targets[0]
        hits = [ts for ts in self._rate_buckets.get(bucket_key, []) if now - ts < self.rate_limit_window_sec]
        self._rate_buckets[bucket_key] = hits
        if len(hits) >= self.rate_limit_max:
            return ScopeDecision(
                False,
                "rate_limited",
                f"Rate limit exceeded for {bucket_key} ({self.rate_limit_max}/{self.rate_limit_window_sec}s)",
                list(targets),
            )
        return None

    def record_execution(self, targets: Sequence[str]) -> None:
        if self.rate_limit_max <= 0 or not targets:
            return
        bucket_key = targets[0]
        self._rate_buckets.setdefault(bucket_key, []).append(time.time())

    def is_destructive_module(self, module) -> bool:
        info = getattr(module, "__info__", None) or {}
        tags = info.get("tags") or []
        if isinstance(tags, (list, tuple, set)):
            lowered = {str(tag).lower() for tag in tags}
            if "destructive" in lowered or "dos" in lowered:
                return True
        if str(info.get("category", "")).lower() in {"dos", "destructive"}:
            return True

        module_path = (
            getattr(module, "name", "")
            or getattr(module, "_module_path", "")
            or ""
        ).lower()
        if any(keyword in module_path for keyword in DESTRUCTIVE_PATH_KEYWORDS):
            return True

        module_type = str(getattr(module, "type", "") or getattr(module, "TYPE_MODULE", "")).lower()
        if module_type in {"dos"}:
            return True

        for attr in ("destructive", "force", "wipe", "delete_data"):
            if hasattr(module, attr):
                try:
                    value = getattr(module, attr)
                    if str(value).lower() in {"1", "true", "yes", "on"}:
                        return True
                except Exception:
                    pass
        return False

    def evaluate_module(self, module) -> ScopeDecision:
        if not self.enabled:
            return ScopeDecision(True, "not_enforced", "Scope enforcement disabled")

        targets = self.extract_targets_from_module(module)
        if not targets:
            return ScopeDecision(
                True,
                "allow",
                "No concrete target resolved; scope allowlist not applied",
                [],
                ["Set target/rhost/url before execution to enforce scope"],
            )

        decisions = [self.is_target_allowed(target) for target in targets]
        denied = [d for d in decisions if not d.allowed]
        if denied:
            decision = denied[0]
            decision.targets = targets
            decision.details = [d.reason for d in denied]
            return decision

        rate_decision = self._check_rate_limit(targets)
        if rate_decision:
            rate_decision.targets = list(targets)
            return rate_decision

        if self.require_confirm_destructive and self.is_destructive_module(module):
            return ScopeDecision(
                True,
                "confirm_required",
                "Destructive module requires operator confirmation",
                list(targets),
            )

        return ScopeDecision(True, "allow", "All targets are in scope", list(targets))

    def check_execution(self, module, *, skip_confirm: bool = False) -> ScopeDecision:
        decision = self.evaluate_module(module)
        self.last_decision = decision

        if not self.enabled:
            return decision

        if not decision.allowed:
            self.audit(
                "execution_denied",
                {
                    "action": decision.action,
                    "reason": decision.reason,
                    "targets": decision.targets,
                    "module": getattr(module, "name", ""),
                },
            )
            return decision

        if decision.action == "confirm_required" and not skip_confirm:
            self.audit(
                "confirmation_required",
                {
                    "targets": decision.targets,
                    "module": getattr(module, "name", ""),
                },
            )
            return decision

        self.audit(
            "execution_allowed",
            {
                "targets": decision.targets,
                "module": getattr(module, "name", ""),
                "action": decision.action,
            },
        )
        self.record_execution(decision.targets)
        return decision

    def mark_execution_allowed(self, module, decision: ScopeDecision) -> None:
        self.audit(
            "execution_allowed",
            {
                "targets": decision.targets,
                "module": getattr(module, "name", ""),
                "action": decision.action,
                "confirmed": True,
            },
        )
        self.record_execution(decision.targets)

    def report_denial(self, decision: ScopeDecision) -> None:
        from core.output_handler import print_error, print_info, print_warning

        prefix = "[SCOPE]"
        if decision.action == "rate_limited":
            print_error(f"{prefix} Rate limit exceeded: {decision.reason}")
        else:
            print_error(f"{prefix} {decision.reason}")
        for detail in decision.details:
            print_info(f"{prefix} {detail}")
        if decision.action == "deny" and self.enabled and not self.allowed_ips and not self.allowed_domains:
            print_info(f"{prefix} Add allowlist entries with: scope allow add ip|domain <value>")

    def ensure_execution_permitted(self, module, *, skip_confirm: bool = False) -> bool:
        """Gate module execution. Returns True when run may proceed."""
        decision = self.check_execution(module, skip_confirm=skip_confirm)
        if not self.enabled:
            return True
        if not decision.allowed:
            self.report_denial(decision)
            return False
        if decision.action == "confirm_required" and not skip_confirm:
            if not self.prompt_destructive_confirm(module, decision.targets):
                self.audit(
                    "confirmation_denied",
                    {"targets": decision.targets, "module": getattr(module, "name", "")},
                )
                return False
            self.mark_execution_allowed(module, decision)
        return True

    def prompt_destructive_confirm(self, module, targets: Sequence[str]) -> bool:
        module_name = getattr(module, "name", "current module")
        print_targets = ", ".join(targets) if targets else "unknown"
        try:
            answer = input(
                f"\n[SCOPE] Destructive action on {print_targets} via '{module_name}'. "
                "Type 'yes' to confirm: "
            ).strip().lower()
        except (EOFError, KeyboardInterrupt):
            answer = ""
        confirmed = answer in {"yes", "y"}
        self.audit(
            "confirmation_response",
            {
                "confirmed": confirmed,
                "targets": list(targets),
                "module": module_name,
            },
        )
        return confirmed

    def preview_lines(self, module) -> List[tuple]:
        lines: List[tuple] = []
        lines.append(("info", f"Enforcement: {'enabled' if self.enabled else 'disabled'}"))
        lines.append(("info", f"Allowlist IPs/CIDRs: {len(self.allowed_ips)}"))
        lines.append(("info", f"Allowlist domains: {len(self.allowed_domains)}"))
        if self.rate_limit_max > 0:
            lines.append(
                (
                    "info",
                    f"Rate limit: {self.rate_limit_max} actions / {self.rate_limit_window_sec}s per target",
                )
            )
        else:
            lines.append(("info", "Rate limit: disabled"))

        decision = self.evaluate_module(module)
        self.last_decision = decision
        if not self.enabled:
            lines.append(("warning", "Status: not enforced while scope is disabled"))
            return lines

        if decision.targets:
            lines.append(("info", f"Resolved targets: {', '.join(decision.targets)}"))
        else:
            lines.append(("warning", "Resolved targets: none (allowlist not evaluated)"))

        if not decision.allowed:
            lines.append(("error", f"Status: BLOCKED — {decision.reason}"))
        elif decision.action == "confirm_required":
            lines.append(("warning", "Status: confirmation required (destructive module)"))
        elif decision.action == "rate_limited":
            lines.append(("error", f"Status: BLOCKED — {decision.reason}"))
        else:
            lines.append(("success", f"Status: {decision.reason}"))

        if self.is_destructive_module(module):
            lines.append(("warning", "Module classified as destructive"))
        return lines
