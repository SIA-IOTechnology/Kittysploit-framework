#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""HTTP client for KittySploit Academy Rooms API (lab VPN sessions)."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

import requests

from core.output_handler import print_error, print_warning

DEFAULT_API_URL = "https://rooms.kittysploit.com"
CONFIG_FILENAME = "rooms_config.json"
USER_AGENT = "KittySploit-Framework/1.0"


def rooms_config_path() -> Path:
    return Path.home() / ".kittysploit" / CONFIG_FILENAME


def load_rooms_config() -> Dict[str, Any]:
    path = rooms_config_path()
    if not path.is_file():
        return {}
    try:
        with open(path, encoding="utf-8") as handle:
            data = json.load(handle)
        return data if isinstance(data, dict) else {}
    except (OSError, json.JSONDecodeError) as exc:
        print_warning(f"Could not read rooms config ({path}): {exc}")
        return {}


def save_rooms_config(updates: Dict[str, Any]) -> Path:
    path = rooms_config_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    current = load_rooms_config()
    current.update({k: v for k, v in updates.items() if v is not None})
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(current, handle, indent=2)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return path


def resolve_api_url(cli_url: Optional[str] = None) -> str:
    if cli_url:
        return cli_url.rstrip("/")
    env = os.environ.get("KITTYSPLOIT_ROOMS_API_URL", "").strip()
    if env:
        return env.rstrip("/")
    cfg = load_rooms_config()
    return str(cfg.get("api_url") or DEFAULT_API_URL).rstrip("/")


def resolve_api_key(cli_key: Optional[str] = None) -> Optional[str]:
    if cli_key:
        return cli_key.strip()
    env = os.environ.get("KITTYSPLOIT_ROOMS_API_KEY", "").strip()
    if env:
        return env
    cfg = load_rooms_config()
    key = cfg.get("api_key")
    return str(key).strip() if key else None


@dataclass
class WireGuardPeerConfig:
    private_key: str
    address: str
    peer_public_key: str
    endpoint: str
    allowed_ips: List[str] = field(default_factory=list)
    persistent_keepalive: int = 25
    dns: Optional[str] = None

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "WireGuardPeerConfig":
        allowed = data.get("allowed_ips") or []
        if isinstance(allowed, str):
            allowed = [a.strip() for a in allowed.split(",") if a.strip()]
        return cls(
            private_key=str(data["private_key"]),
            address=str(data["address"]),
            peer_public_key=str(data["peer_public_key"]),
            endpoint=str(data["endpoint"]),
            allowed_ips=[str(a) for a in allowed],
            persistent_keepalive=int(data.get("persistent_keepalive") or 25),
            dns=str(data["dns"]) if data.get("dns") else None,
        )

    def to_wg_quick_conf(self, interface_name: str = "ksroom0") -> str:
        """Render a wg-quick compatible configuration (split-tunnel only)."""
        if not self.allowed_ips:
            raise ValueError("allowed_ips must not be empty (split-tunnel required)")
        if any(ip.strip() in ("0.0.0.0/0", "::/0") for ip in self.allowed_ips):
            raise ValueError("Full-tunnel AllowedIPs (0.0.0.0/0) are not allowed for Rooms")

        lines = [
            "[Interface]",
            f"# KittySploit Room interface={interface_name}",
            f"PrivateKey = {self.private_key}",
            f"Address = {self.address}",
        ]
        if self.dns:
            lines.append(f"DNS = {self.dns}")
        lines.extend(
            [
                "",
                "[Peer]",
                f"PublicKey = {self.peer_public_key}",
                f"Endpoint = {self.endpoint}",
                f"AllowedIPs = {', '.join(self.allowed_ips)}",
                f"PersistentKeepalive = {self.persistent_keepalive}",
                "",
            ]
        )
        return "\n".join(lines)


@dataclass
class RoomSession:
    session_id: str
    room_id: str
    mode: str
    subnet: str
    expires_at: str
    wireguard: WireGuardPeerConfig
    targets: List[Dict[str, Any]] = field(default_factory=list)
    roe: str = ""
    raw: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "RoomSession":
        wg = data.get("wireguard")
        if not isinstance(wg, dict):
            raise ValueError("Response missing wireguard block")
        return cls(
            session_id=str(data["session_id"]),
            room_id=str(data["room_id"]),
            mode=str(data.get("mode") or "training"),
            subnet=str(data["subnet"]),
            expires_at=str(data.get("expires_at") or ""),
            wireguard=WireGuardPeerConfig.from_dict(wg),
            targets=list(data.get("targets") or []),
            roe=str(data.get("roe") or ""),
            raw=data,
        )


class RoomClient:
    """Client for Academy Rooms control-plane API."""

    def __init__(
        self,
        api_url: Optional[str] = None,
        api_key: Optional[str] = None,
        timeout: float = 30.0,
    ):
        self.api_url = resolve_api_url(api_url)
        self.api_key = resolve_api_key(api_key)
        self.timeout = timeout
        self.session = requests.Session()
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": USER_AGENT,
        }
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        self.session.headers.update(headers)
        self.connected = False
        self.current: Optional[RoomSession] = None

    def test_connection(self) -> bool:
        try:
            response = self.session.get(f"{self.api_url}/api/v1/status", timeout=self.timeout)
            if response.status_code == 200:
                self.connected = True
                return True
            print_error(f"Rooms API status failed: HTTP {response.status_code}")
            return False
        except requests.exceptions.RequestException as exc:
            print_error(f"Rooms API unreachable ({self.api_url}): {exc}")
            return False

    def claim_token(self, token: str) -> Optional[RoomSession]:
        token = (token or "").strip()
        if not token:
            print_error("Room token is required")
            return None
        try:
            response = self.session.post(
                f"{self.api_url}/api/v1/sessions/claim",
                json={"token": token},
                timeout=self.timeout,
            )
            return self._parse_session_response(response, "claim token")
        except requests.exceptions.RequestException as exc:
            print_error(f"Claim failed: {exc}")
            return None

    def connect_room(self, slug: str) -> Optional[RoomSession]:
        slug = (slug or "").strip()
        if not slug:
            print_error("Room slug is required")
            return None
        if not self.api_key:
            print_error("API key required for room connect by slug (room config --api-key …)")
            return None
        try:
            response = self.session.post(
                f"{self.api_url}/api/v1/rooms/{slug}/connect",
                json={},
                timeout=self.timeout,
            )
            return self._parse_session_response(response, f"connect room {slug}")
        except requests.exceptions.RequestException as exc:
            print_error(f"Connect room failed: {exc}")
            return None

    def list_rooms(self) -> List[Dict[str, Any]]:
        if not self.api_key:
            print_error("API key required for room list")
            return []
        try:
            response = self.session.get(f"{self.api_url}/api/v1/rooms", timeout=self.timeout)
            if response.status_code != 200:
                print_error(f"List rooms failed: HTTP {response.status_code} — {response.text[:200]}")
                return []
            data = response.json()
            if isinstance(data, list):
                return data
            return list(data.get("rooms") or [])
        except requests.exceptions.RequestException as exc:
            print_error(f"List rooms failed: {exc}")
            return []
        except (ValueError, TypeError) as exc:
            print_error(f"Invalid list rooms response: {exc}")
            return []

    def heartbeat(self, session_id: Optional[str] = None) -> bool:
        sid = session_id or (self.current.session_id if self.current else None)
        if not sid:
            return False
        try:
            response = self.session.post(
                f"{self.api_url}/api/v1/sessions/{sid}/heartbeat",
                json={},
                timeout=self.timeout,
            )
            return response.status_code in (200, 204)
        except requests.exceptions.RequestException:
            return False

    def revoke_session(self, session_id: Optional[str] = None) -> bool:
        sid = session_id or (self.current.session_id if self.current else None)
        if not sid:
            print_error("No room session to revoke")
            return False
        try:
            response = self.session.delete(
                f"{self.api_url}/api/v1/sessions/{sid}",
                timeout=self.timeout,
            )
            ok = response.status_code in (200, 204)
            if ok and self.current and self.current.session_id == sid:
                self.current = None
            if not ok:
                print_error(f"Revoke failed: HTTP {response.status_code} — {response.text[:200]}")
            return ok
        except requests.exceptions.RequestException as exc:
            print_error(f"Revoke failed: {exc}")
            return False

    def _parse_session_response(
        self, response: requests.Response, action: str
    ) -> Optional[RoomSession]:
        if response.status_code not in (200, 201):
            print_error(f"{action} failed: HTTP {response.status_code} — {response.text[:300]}")
            return None
        try:
            data = response.json()
            room_session = RoomSession.from_dict(data)
            self.current = room_session
            self.connected = True
            return room_session
        except (ValueError, KeyError, TypeError) as exc:
            print_error(f"Invalid session payload: {exc}")
            return None
