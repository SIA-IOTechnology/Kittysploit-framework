#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Academy Rooms — connect WireGuard lab tunnel, scope, and target brief."""

from __future__ import annotations

import argparse
from typing import Any, Dict, List, Optional

from core.output_handler import (
    print_empty,
    print_error,
    print_info,
    print_success,
    print_table,
    print_warning,
)
from core.room_client import (
    RoomClient,
    RoomSession,
    load_rooms_config,
    resolve_api_key,
    resolve_api_url,
    rooms_config_path,
    save_rooms_config,
)
from core.wireguard_manager import WireGuardManager
from interfaces.command_system.base_command import BaseCommand

ACTIONS = ("connect", "status", "disconnect", "list", "config", "install-wg")


class RoomCommand(BaseCommand):
    """Connect to an Academy Room (lab VPN) with minimal user interaction."""

    @property
    def name(self) -> str:
        return "room"

    @property
    def aliases(self) -> List[str]:
        return ["connect"]

    @property
    def description(self) -> str:
        return "Connect to Academy Rooms (WireGuard lab tunnel + scope + targets)"

    @property
    def usage(self) -> str:
        return (
            "room connect (--token TOKEN | --room SLUG) [--api-url URL] [--api-key KEY] [--yes] [--dry-run]\n"
            "       room status | disconnect | list | config | install-wg\n"
            "       connect --token TOKEN ...   (alias)"
        )

    @property
    def help_text(self) -> str:
        return f"""
{self.description}

Usage:
  {self.usage}

If WireGuard is missing, `room connect` offers to install it (y/N) via winget/brew/apt.
Use `room install-wg` to install without connecting, or `--yes` to skip the prompt.

Subcommands:
  connect       Claim a room session, bring up WG split-tunnel, enable scope
  status        Show local tunnel + session info
  disconnect    Tear down tunnel, revoke session, clear room scope entry
  list          List rooms assigned to your API key
  config        Show or set api_url / api_key (~/.kittysploit/rooms_config.json)
  install-wg    Install WireGuard via the system package manager

Examples:
  room connect --token ks_room_...
  room connect --room kso-01 --yes
  connect --token ks_room_... --api-url http://127.0.0.1:8090
  room install-wg
  room status
  room disconnect
  room config --api-url https://rooms.kittysploit.com --api-key YOUR_KEY
"""

    def get_subcommands(self):
        return list(ACTIONS)

    def execute(self, args: List[str], **kwargs) -> bool:
        normalized = self._normalize_args(list(args or []))
        if not normalized or normalized[0] in ("-h", "--help", "help"):
            print_info(self.help_text)
            return True

        parser = self._create_parser()
        try:
            parsed = parser.parse_args(normalized)
        except SystemExit:
            return False

        action = parsed.action
        if action == "connect":
            return self._cmd_connect(parsed)
        if action == "status":
            return self._cmd_status(parsed)
        if action == "disconnect":
            return self._cmd_disconnect(parsed)
        if action == "list":
            return self._cmd_list(parsed)
        if action == "config":
            return self._cmd_config(parsed)
        if action == "install-wg":
            return self._cmd_install_wg(parsed)
        print_error(f"Unknown action: {action}")
        return False

    def _normalize_args(self, args: List[str]) -> List[str]:
        """Allow `connect --token ...` (alias) without repeating the subcommand."""
        if not args:
            return ["status"]
        if args[0] in ACTIONS:
            return args
        # Flags-only -> default to connect (alias UX)
        if args[0].startswith("-"):
            return ["connect"] + args
        return args

    def _create_parser(self) -> argparse.ArgumentParser:
        parser = argparse.ArgumentParser(
            prog="room",
            description=self.description,
            add_help=False,
        )
        sub = parser.add_subparsers(dest="action", required=True)

        connect = sub.add_parser("connect", add_help=False)
        connect.add_argument("--token", default=None, help="Opaque room token (ks_room_...)")
        connect.add_argument(
            "--room",
            nargs="?",
            const="",
            default=None,
            help="Room slug (API key auth), or flag with --token",
        )
        connect.add_argument("--api-url", default=None, help="Rooms API base URL")
        connect.add_argument("--api-key", default=None, help="Account API key")
        connect.add_argument(
            "--dry-run",
            action="store_true",
            help="Claim + write conf without activating WireGuard",
        )
        connect.add_argument(
            "--no-verify",
            action="store_true",
            help="Skip post-connect HTTP reachability check",
        )
        connect.add_argument(
            "--yes",
            "-y",
            action="store_true",
            help="Auto-install WireGuard without prompting if missing",
        )

        status = sub.add_parser("status", add_help=False)
        status.add_argument("--api-url", default=None)
        status.add_argument("--api-key", default=None)

        disconnect = sub.add_parser("disconnect", add_help=False)
        disconnect.add_argument("--api-url", default=None)
        disconnect.add_argument("--api-key", default=None)
        disconnect.add_argument("--dry-run", action="store_true")

        list_p = sub.add_parser("list", add_help=False)
        list_p.add_argument("--api-url", default=None)
        list_p.add_argument("--api-key", default=None)

        config = sub.add_parser("config", add_help=False)
        config.add_argument("--api-url", default=None)
        config.add_argument("--api-key", default=None)
        config.add_argument("--show", action="store_true")

        install_wg = sub.add_parser("install-wg", add_help=False)
        install_wg.add_argument(
            "--yes",
            "-y",
            action="store_true",
            help="Install without confirmation prompt",
        )

        return parser

    def _client(self, api_url: Optional[str], api_key: Optional[str]) -> RoomClient:
        return RoomClient(api_url=api_url, api_key=api_key)

    def _wg(self) -> WireGuardManager:
        existing = getattr(self.framework, "room_wg", None)
        if isinstance(existing, WireGuardManager):
            return existing
        mgr = WireGuardManager()
        self.framework.room_wg = mgr
        return mgr

    def _cmd_connect(self, args: argparse.Namespace) -> bool:
        token = (args.token or "").strip() or None
        room_opt = args.room  # None | "" | "slug"

        if not token and room_opt in (None, ""):
            print_error("Provide --token ks_room_... or --room <slug>")
            return False

        client = self._client(args.api_url, args.api_key)
        print_info(f"Rooms API: {client.api_url}")

        session: Optional[RoomSession] = None
        if token:
            print_info("Claiming room session with token...")
            session = client.claim_token(token)
        else:
            slug = (room_opt or "").strip()
            print_info(f"Connecting to room '{slug}'...")
            session = client.connect_room(slug)

        if not session:
            return False

        wg = self._wg()
        verify_url = None
        if not args.no_verify and session.targets:
            verify_url = session.targets[0].get("url") or None

        if not wg.up(
            session.wireguard,
            dry_run=args.dry_run,
            verify_url=None,
            offer_install=True,
            auto_install=bool(getattr(args, "yes", False)),
        ):
            if not args.dry_run:
                print_warning("Tunnel failed — session revoked, you can retry room connect.")
                client.revoke_session(session.session_id)
            return False

        # Soft reachability after peer was applied server-side during claim
        if not args.dry_run and verify_url and not getattr(args, "no_verify", False):
            import time

            print_info("Waiting for lab reachability...")
            time.sleep(3)
            if not wg.verify_reachability(verify_url, timeout=20.0):
                print_warning(
                    "Tunnel is up but target not reachable yet. "
                    "Try again in a few seconds, or check VPS: docker exec ks-rooms-wg wg show"
                )

        if not args.dry_run:
            self._apply_workspace_and_scope(session)
            self.framework.room_session = {
                "session": session,
                "client": client,
                "api_url": client.api_url,
            }
            # Prompt hint for CLI if supported
            try:
                self.framework.room_prompt_tag = f"ROOM:{session.room_id}"
            except Exception:
                pass

        self._print_brief(session, dry_run=args.dry_run)
        return True

    def _apply_workspace_and_scope(self, session: RoomSession) -> None:
        ws_name = f"room-{session.room_id}"
        wm = getattr(self.framework, "workspace_manager", None)
        if wm is not None:
            try:
                current = wm.get_current_workspace()
                if not current or getattr(current, "name", None) != ws_name:
                    names = {getattr(w, "name", None) for w in (wm.list_workspaces() or [])}
                    if ws_name not in names:
                        wm.create_workspace(
                            ws_name,
                            description=f"Academy Room {session.room_id} ({session.mode})",
                        )
                    wm.switch_workspace(ws_name)
            except Exception as exc:
                print_warning(f"Workspace setup skipped: {exc}")

        sm = getattr(self.framework, "scope_manager", None)
        if sm is None:
            try:
                from core.scope_manager import ScopeManager

                sm = ScopeManager(workspace=ws_name)
                self.framework.scope_manager = sm
            except Exception as exc:
                print_warning(f"Scope manager unavailable: {exc}")
                return

        try:
            sm.enable()
            sm.add_allow_ip(session.subnet)
            for target in session.targets:
                host = target.get("host")
                if host:
                    try:
                        sm.add_allow_ip(str(host))
                    except Exception:
                        pass
            print_success(f"Scope enabled for {session.subnet}")
        except Exception as exc:
            print_warning(f"Scope setup incomplete: {exc}")

    def _print_brief(self, session: RoomSession, dry_run: bool = False) -> None:
        print_empty()
        print_success(
            f"Room {session.room_id} ready"
            + (" [dry-run]" if dry_run else "")
            + f"  mode={session.mode}  expires={session.expires_at or 'n/a'}"
        )
        print_info(f"Session: {session.session_id}")
        print_info(f"Subnet:  {session.subnet} (split-tunnel only)")
        if session.roe:
            print_info(f"ROE:     {session.roe}")
        print_empty()
        if session.targets:
            rows = []
            for t in session.targets:
                ports = t.get("ports") or []
                if isinstance(ports, list):
                    ports_s = ",".join(str(p) for p in ports)
                else:
                    ports_s = str(ports)
                rows.append(
                    [
                        str(t.get("name") or ""),
                        str(t.get("host") or ""),
                        ports_s,
                        str(t.get("url") or ""),
                    ]
                )
            print_info("Targets:")
            print_table(["Name", "Host", "Ports", "URL"], rows)
        else:
            print_warning("No targets in session payload")
        print_empty()
        print_info("Next: use modules against the targets above, then `room disconnect`.")

    def _cmd_status(self, args: argparse.Namespace) -> bool:
        wg = self._wg()
        st = wg.status()
        print_info(f"Platform:   {st['platform']}")
        if st["available"]:
            print_info("WG tooling: yes")
        else:
            print_warning("WG tooling: NO (WireGuard not installed)")
            print_empty()
            for line in wg.install_help_lines():
                print_info(line)
            print_empty()
        print_info(f"Conf:       {st['conf_path']} ({'exists' if st['conf_exists'] else 'missing'})")
        print_info(f"Tunnel:     {'UP' if st['active'] else 'down'}")

        room = getattr(self.framework, "room_session", None)
        if room and room.get("session"):
            session: RoomSession = room["session"]
            print_empty()
            print_success(f"Active session: {session.room_id} ({session.session_id})")
            print_info(f"Mode:    {session.mode}")
            print_info(f"Subnet:  {session.subnet}")
            print_info(f"Expires: {session.expires_at or 'n/a'}")
            print_info(f"API:     {room.get('api_url')}")
            if session.targets:
                for t in session.targets:
                    print_info(f"Target:  {t.get('name')} -> {t.get('url') or t.get('host')}")
        else:
            print_warning("No room session attached to this framework process")

        sm = getattr(self.framework, "scope_manager", None)
        if sm is not None:
            try:
                sd = sm.status_dict()
                print_info(
                    f"Scope:    enabled={sd.get('enabled')} ips={sd.get('allowed_ips')}"
                )
            except Exception:
                pass
        return True

    def _cmd_disconnect(self, args: argparse.Namespace) -> bool:
        room = getattr(self.framework, "room_session", None)
        session: Optional[RoomSession] = room.get("session") if room else None
        client: Optional[RoomClient] = room.get("client") if room else None

        wg = self._wg()
        wg.down(dry_run=args.dry_run)

        if session and client and not args.dry_run:
            client.revoke_session(session.session_id)
            # Remove room subnet from scope if present
            sm = getattr(self.framework, "scope_manager", None)
            if sm is not None:
                try:
                    sm.remove_allow_ip(session.subnet)
                except Exception:
                    pass

        if hasattr(self.framework, "room_session"):
            self.framework.room_session = None
        if hasattr(self.framework, "room_prompt_tag"):
            self.framework.room_prompt_tag = None

        print_info("Remember to stop any local listeners started for this room.")
        return True

    def _cmd_list(self, args: argparse.Namespace) -> bool:
        client = self._client(args.api_url, args.api_key)
        rooms = client.list_rooms()
        if not rooms:
            print_warning("No rooms returned (check API key / assignments)")
            return True
        rows = []
        for r in rooms:
            rows.append(
                [
                    str(r.get("slug") or r.get("room_id") or r.get("id") or ""),
                    str(r.get("status") or ""),
                    str(r.get("mode") or ""),
                    str(r.get("subnet") or ""),
                    str(r.get("expires_at") or ""),
                ]
            )
        print_info("Rooms:")
        print_table(["Slug", "Status", "Mode", "Subnet", "Expires"], rows)
        return True

    def _cmd_config(self, args: argparse.Namespace) -> bool:
        if args.api_url or args.api_key:
            path = save_rooms_config(
                {
                    "api_url": args.api_url,
                    "api_key": args.api_key,
                }
            )
            print_success(f"Saved rooms config -> {path}")

        cfg = load_rooms_config()
        print_info(f"api_url: {resolve_api_url(cfg.get('api_url'))}")
        key = resolve_api_key(cfg.get("api_key") if not args.api_key else args.api_key)
        if key:
            masked = key[:4] + "..." + key[-4:] if len(key) > 8 else "****"
            print_info(f"api_key: {masked}")
        else:
            print_info("api_key: (not set)")
        print_info(f"file:    {rooms_config_path()}")
        return True

    def _cmd_install_wg(self, args: argparse.Namespace) -> bool:
        wg = self._wg()
        if wg.detect()["available"]:
            print_success("WireGuard is already installed.")
            return True
        return wg.ensure_installed(
            ask_confirmation=not bool(getattr(args, "yes", False)),
            auto_yes=bool(getattr(args, "yes", False)),
        )
