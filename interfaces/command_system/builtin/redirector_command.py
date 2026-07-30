#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Generate C2 redirector configs (nginx / Apache / Caddy) for HTTP polling beacons.
"""

from __future__ import annotations

import argparse
from typing import List, Optional

from interfaces.command_system.base_command import BaseCommand
from core.output_handler import print_error, print_info, print_success, print_warning
from lib.c2.beacon_profile import BeaconProfile
from lib.c2.redirector import (
    SUPPORTED_ENGINES,
    RedirectorSpec,
    default_output_dir,
    fronting_hints,
    generate,
    write_redirector,
)


class RedirectorCommand(BaseCommand):
    """Generate reverse-proxy configs that hide the HTTP polling teamserver."""

    @property
    def name(self) -> str:
        return "redirector"

    @property
    def aliases(self) -> List[str]:
        return ["redir"]

    @property
    def description(self) -> str:
        return "Generate nginx/Apache/Caddy C2 redirector configs"

    @property
    def usage(self) -> str:
        return (
            "redirector generate <nginx|apache|caddy> [options] | "
            "redirector show | redirector hints"
        )

    @property
    def help_text(self) -> str:
        return """
Generate reverse-proxy configs that only forward KittySploit HTTP polling
endpoints (/c2/poll, /c2/result) to your teamserver, serve decoy paths locally,
and return 404 for everything else.

Subcommands:
    generate <engine>   Write nginx, apache, or caddy config
    show                Print config to stdout (same options as generate)
    hints               Show domain-fronting option mapping
    help                Show this help

Options (generate / show):
    --backend-host HOST     Teamserver host (default: module lhost or 127.0.0.1)
    --backend-port PORT     Teamserver port (default: module lport or 8088)
    --prefix PATH           URL prefix (default: /c2)
    --listen-port PORT      Redirector listen port (default: 443)
    --server-name NAME      server_name / ServerName (default: _)
    --comms-host HOST       Public CDN/front host implants connect to
    --host-header HOST      Domain-front Host header toward origin/backend
    --tls                   Enable TLS blocks in the generated config
    --ssl-cert PATH         TLS certificate path
    --ssl-key PATH          TLS private key path
    --out DIR               Output directory (default: ~/.kittysploit/redirectors)
    --stdout                Print instead of writing a file (generate)

Domain fronting:
    payload_comms_host  CDN/front host implants connect to
    host_header         Host header value toward origin/backend

Examples:
    use listeners/multi/reverse_http_polling
    set lport 8088
    redirector generate nginx
    redirector generate apache --comms-host cdn.example.com --host-header origin.example.com --tls
    redirector show caddy --backend-host 10.0.0.5 --backend-port 8088
    redirector hints --comms-host cdn.example.com --host-header origin.example.com
        """

    def get_subcommands(self) -> List[str]:
        return ["generate", "show", "hints", "help"]

    def execute(self, args: List[str], **kwargs) -> bool:
        if not args or args[0] in ("-h", "--help", "help"):
            self.show_help()
            return True

        sub = args[0].lower()
        rest = args[1:]

        if sub == "generate":
            return self._generate(rest, to_stdout=False)
        if sub == "show":
            return self._generate(rest, to_stdout=True)
        if sub == "hints":
            return self._hints(rest)

        print_error(f"Unknown subcommand: {sub}")
        print_info("Available: generate, show, hints, help")
        return False

    def _create_parser(self, prog: str) -> argparse.ArgumentParser:
        parser = argparse.ArgumentParser(prog=prog, add_help=True)
        parser.add_argument(
            "engine",
            nargs="?",
            default="nginx",
            help=f"Engine: {', '.join(SUPPORTED_ENGINES)}",
        )
        parser.add_argument("--backend-host", default=None)
        parser.add_argument("--backend-port", type=int, default=None)
        parser.add_argument("--prefix", default=None, help="URI prefix (default /c2)")
        parser.add_argument("--listen-port", type=int, default=443)
        parser.add_argument("--server-name", default="_")
        parser.add_argument("--comms-host", default="", help="payload_comms_host / CDN host")
        parser.add_argument("--host-header", default="", help="host_header toward origin")
        parser.add_argument("--tls", action="store_true")
        parser.add_argument("--ssl-cert", default="/etc/ssl/certs/redirector.crt")
        parser.add_argument("--ssl-key", default="/etc/ssl/private/redirector.key")
        parser.add_argument("--out", default=None, help="Output directory")
        parser.add_argument(
            "--stdout",
            action="store_true",
            help="Print config instead of writing a file",
        )
        return parser

    def _workspace_name(self) -> Optional[str]:
        try:
            wm = getattr(self.framework, "workspace_manager", None)
            if not wm:
                return None
            ws = wm.get_current_workspace()
            return getattr(ws, "name", None) if ws else None
        except Exception:
            return None

    def _resolve_spec(self, parsed: argparse.Namespace) -> RedirectorSpec:
        module = None
        try:
            module = self.session.get_current_module() if self.session else None
        except Exception:
            module = None

        overrides: dict = {
            "listen_port": int(parsed.listen_port or 443),
            "server_name": str(parsed.server_name or "_"),
            "use_tls": bool(parsed.tls),
            "ssl_cert": parsed.ssl_cert,
            "ssl_key": parsed.ssl_key,
        }
        if parsed.backend_host:
            overrides["backend_host"] = parsed.backend_host
        if parsed.backend_port is not None:
            overrides["backend_port"] = parsed.backend_port
        if parsed.prefix:
            overrides["uri_prefix"] = parsed.prefix
        if parsed.comms_host:
            overrides["payload_comms_host"] = parsed.comms_host
        if parsed.host_header:
            overrides["domain_front_header"] = parsed.host_header

        if module is not None:
            try:
                info = getattr(module, "__info__", None) or {}
                protocol = str(info.get("protocol") or "")
                # Prefer HTTP polling listener; still accept any module with matching opts
                if protocol == "http_polling" or hasattr(module, "url_prefix"):
                    return RedirectorSpec.from_module(module, **overrides)
            except Exception as exc:
                print_warning(f"Could not read current module options: {exc}")

        # Also try an active reverse_http_polling listener
        active = getattr(self.framework, "active_listeners", None) or {}
        for listener in active.values():
            try:
                info = getattr(listener, "__info__", None) or {}
                if str(info.get("protocol") or "") == "http_polling":
                    return RedirectorSpec.from_module(listener, **overrides)
            except Exception:
                continue

        profile = BeaconProfile(
            host_header=str(parsed.host_header or ""),
            payload_comms_host=str(parsed.comms_host or ""),
        )
        return RedirectorSpec.from_profile(
            profile,
            backend_host=str(parsed.backend_host or "127.0.0.1"),
            backend_port=int(parsed.backend_port or 8088),
            uri_prefix=str(parsed.prefix or "/c2"),
            listen_port=int(parsed.listen_port or 443),
            server_name=str(parsed.server_name or "_"),
            use_tls=bool(parsed.tls),
            ssl_cert=parsed.ssl_cert,
            ssl_key=parsed.ssl_key,
            domain_front_header=parsed.host_header,
            payload_comms_host=parsed.comms_host,
        )

    def _generate(self, args: List[str], *, to_stdout: bool) -> bool:
        parser = self._create_parser("redirector generate" if not to_stdout else "redirector show")
        try:
            parsed = parser.parse_args(args)
        except SystemExit:
            return False

        engine = str(parsed.engine or "nginx").strip().lower()
        if engine not in SUPPORTED_ENGINES and engine not in ("httpd", "apache2"):
            print_error(f"Unsupported engine: {engine}")
            print_info(f"Use one of: {', '.join(SUPPORTED_ENGINES)}")
            return False

        try:
            spec = self._resolve_spec(parsed)
            text = generate(engine, spec)
        except Exception as exc:
            print_error(f"Failed to generate redirector config: {exc}")
            return False

        if to_stdout or parsed.stdout:
            print(text)
            return True

        out_dir = parsed.out or str(default_output_dir(self._workspace_name()))
        try:
            path = write_redirector(engine, spec, output_dir=out_dir)
        except Exception as exc:
            print_error(f"Failed to write config: {exc}")
            return False

        print_success(f"Wrote {engine} redirector config: {path}")
        print_info(f"Backend {spec.backend}  paths {spec.poll_uri} {spec.result_uri}")
        if spec.payload_comms_host or spec.domain_front_header:
            hints = fronting_hints(spec)
            print_info(
                f"Fronting: payload_comms_host={hints['payload_comms_host']}  "
                f"host_header={hints['host_header']}"
            )
            print_info(
                "Payload: set payload_comms_host / host_header to match, "
                "lhost/lport = teamserver (or leave connect via CDN)."
            )
        return True

    def _hints(self, args: List[str]) -> bool:
        parser = self._create_parser("redirector hints")
        try:
            # engine unused for hints
            if args and args[0] in SUPPORTED_ENGINES:
                args = args[1:]
            parsed = parser.parse_args(["nginx"] + list(args))
        except SystemExit:
            return False

        spec = self._resolve_spec(parsed)
        hints = fronting_hints(spec)
        print_info("KittySploit domain-fronting options")
        print(f"  payload_comms_host = {hints['payload_comms_host']}")
        print(f"  host_header        = {hints['host_header']}")
        print(f"  payload set payload_comms_host <CDN host>")
        print(f"  payload set host_header <origin Host>")
        print(f"  Backend teamserver = {hints['backend']}")
        print(f"  C2 URIs            = {hints['poll']}  {hints['result']}")
        return True
