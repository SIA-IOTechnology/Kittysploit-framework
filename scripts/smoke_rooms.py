#!/usr/bin/env python3
"""Smoke test for Rooms client + room command (dry-run)."""

from __future__ import annotations

import sqlite3
import sys
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from core.room_client import RoomClient, WireGuardPeerConfig
from core.wireguard_manager import WireGuardManager
from interfaces.command_system.builtin.room_command import RoomCommand


def test_conf_split_tunnel() -> None:
    peer = WireGuardPeerConfig(
        private_key="A" * 44,
        address="10.66.0.2/32",
        peer_public_key="B" * 44,
        endpoint="127.0.0.1:51820",
        allowed_ips=["10.66.0.0/24"],
    )
    text = peer.to_wg_quick_conf()
    assert "AllowedIPs = 10.66.0.0/24" in text
    try:
        WireGuardPeerConfig(
            private_key="A",
            address="x",
            peer_public_key="B",
            endpoint="e",
            allowed_ips=["0.0.0.0/0"],
        ).to_wg_quick_conf()
        raise AssertionError("full tunnel should be rejected")
    except ValueError:
        pass


def test_api_and_command() -> None:
    api = "http://127.0.0.1:8090"
    client = RoomClient(api_url=api, api_key="ks_rooms_demo_key")
    if not client.test_connection():
        print("SKIP: Rooms API not running on :8090")
        return

    db = ROOT / "docs" / "academy" / "rooms_api" / "data" / "rooms.db"
    conn = sqlite3.connect(str(db))
    conn.execute(
        "INSERT OR REPLACE INTO tokens (token, room_slug, expires_at, used) "
        "VALUES (?, ?, ?, 0)",
        ("ks_room_test2", "kso-01", "2099-01-01T00:00:00Z"),
    )
    conn.commit()
    conn.close()

    fw = SimpleNamespace()
    cmd = RoomCommand(fw, None, None)
    assert cmd.execute(
        [
            "connect",
            "--token",
            "ks_room_test2",
            "--api-url",
            api,
            "--dry-run",
            "--no-verify",
        ]
    )
    assert cmd.execute(["status"])
    # Alias-style: flags first -> connect
    assert cmd._normalize_args(["--token", "x", "--api-url", api])[0] == "connect"
    print("room command dry-run OK")


def main() -> int:
    test_conf_split_tunnel()
    assert WireGuardManager().up(
        WireGuardPeerConfig(
            private_key="A" * 44,
            address="10.66.0.2/32",
            peer_public_key="B" * 44,
            endpoint="127.0.0.1:51820",
            allowed_ips=["10.66.0.0/24"],
        ),
        dry_run=True,
    )
    test_api_and_command()
    print("ALL SMOKE TESTS PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
