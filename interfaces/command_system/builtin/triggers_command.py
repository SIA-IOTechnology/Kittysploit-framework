#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Manage automatic session lifecycle triggers."""

import argparse
from typing import Any, Dict, List, Tuple

from interfaces.command_system.base_command import BaseCommand
from core.output_handler import print_info, print_success, print_error
from core.session_triggers import SessionTrigger, SessionTriggerAction, SessionTriggerManager


def _parse_opt_pair(raw: str) -> Tuple[str, str]:
    text = str(raw or "").strip()
    if "=" not in text:
        return "", ""
    key, _, value = text.partition("=")
    return key.strip(), value.strip()


def _split_csv(raw: str) -> List[str]:
    return [part.strip() for part in str(raw or "").split(",") if part.strip()]


def _strip_quotes(value: str) -> str:
    text = str(value or "").strip()
    if len(text) >= 2 and text[0] == text[-1] and text[0] in ("'", '"'):
        return text[1:-1]
    return text


def _trailing_module_options(tokens: List[str]) -> Tuple[Dict[str, Any], List[str]]:
    """Treat leftover NAME=VALUE tokens (without --opt) as module options."""
    options: Dict[str, Any] = {}
    unknown: List[str] = []
    for token in tokens or []:
        if token in ("--",):
            continue
        key, value = _parse_opt_pair(token)
        if key and "=" in token and not token.startswith("-"):
            options[key] = _strip_quotes(value)
        else:
            unknown.append(token)
    return options, unknown


class TriggersCommand(BaseCommand):
    @property
    def name(self) -> str:
        return "triggers"

    @property
    def description(self) -> str:
        return "Manage automatic actions on session lifecycle events"

    @property
    def usage(self) -> str:
        return "triggers [list|add|remove|enable|disable] [options]"

    @property
    def help_text(self) -> str:
        return f"""
{self.description}

Usage: {self.usage}

Subcommands:
    list                         List triggers for the current workspace
    add                          Register a new trigger rule
    remove <index>               Remove trigger by index (see list)
    enable                       Turn on all triggers (runtime)
    disable                      Turn off all triggers (runtime)

Events:
    session.created              Fires when a new session is registered
    session.reconnected          Durable / beacon session back online
    session.closed               Session removed or disconnected

Actions (combine one or more on the same rule):
    --command CMD                Run a native session command (shell / meterpreter / …)
    --module PATH                Run a module with SESSION_ID preset (post/, browser_auxiliary/, …)
    --tag LABEL                  Append a tag to session metadata
    --opt NAME=VALUE             Module option (repeatable; only applies with --module)

Filters (optional, comma-separated):
    --types TYPES                Session types, e.g. shell,meterpreter,browser,http_cmd
    --listeners PATHS            Only sessions from matching listener module paths
    --platforms PLATFORMS        Match session platform/os metadata (linux, windows, …)
    --name LABEL                 Human-readable label in list output

Module notes:
    The trigger sets session_id on the module before run(). Use --opt for any other option
    (same names as in the module: show options / set). Rules are stored per workspace.
    Browser hook sessions (browser_server) use session type browser and fire session.created
    when the victim first registers.

    Browser hook example (alert on every new browser JS session):
        triggers add --event session.created --types browser \\
            --module browser_auxiliary/misc/alert --opt message=KittySploit
        triggers add --event session.created --types browser \\
            --module browser_auxiliary/misc/alert message=KittySploit

    Post-exploit example:
        triggers add --event session.created --types shell --platforms linux \\
            --module post/shell/linux/gather/sysinfo --name linux-sysinfo

Shell command examples:
    triggers list
    triggers add --event session.created --command sysinfo --types meterpreter
    triggers add --event session.created --tag hooked --types browser
    triggers remove 0
        """

    def __init__(self, framework, session, output_handler):
        super().__init__(framework, session, output_handler)
        self.add_parser = self._create_add_parser()

    def _manager(self) -> SessionTriggerManager:
        mgr = getattr(self.framework, "session_trigger_manager", None)
        if mgr is None:
            raise RuntimeError("Session trigger manager is not initialized")
        return mgr

    def _create_add_parser(self) -> argparse.ArgumentParser:
        """Parser for 'triggers add' only (no positionals that steal NAME=VALUE tokens)."""
        parser = argparse.ArgumentParser(prog="triggers add", add_help=False)
        parser.add_argument("--event", required=True, help="Trigger event name")
        parser.add_argument("--command", help="Shell/meterpreter (or session-native) command")
        parser.add_argument("--module", help="Module path (post/..., browser_auxiliary/..., etc.)")
        parser.add_argument(
            "--opt",
            "--set",
            action="append",
            default=[],
            dest="module_opts",
            metavar="NAME=VALUE",
            help="Module option (repeatable; used with --module)",
        )
        parser.add_argument("--tag", help="Tag to apply to the session")
        parser.add_argument("--types", help="Comma-separated session type filter")
        parser.add_argument("--listeners", help="Comma-separated listener module path filter")
        parser.add_argument("--platforms", help="Comma-separated platform/os filter")
        parser.add_argument("--name", help="Optional trigger label")
        return parser

    def execute(self, args, **kwargs) -> bool:
        if not args:
            return self._list_triggers()

        sub = str(args[0]).lower()
        rest = args[1:]
        try:
            if sub in ("help", "-h", "--help"):
                print_info(self.help_text)
                return True
            if sub == "list":
                return self._list_triggers()
            if sub == "add":
                return self._add_trigger_args(rest)
            if sub == "remove":
                return self._remove_trigger_index(rest)
            if sub == "enable":
                return self._set_enabled(True)
            if sub == "disable":
                return self._set_enabled(False)
            print_error(f"Unknown subcommand: {sub}")
            print_info("Use: triggers list|add|remove|enable|disable|help")
            return False
        except SystemExit:
            return True
        except Exception as exc:
            print_error(f"Triggers command failed: {exc}")
            return False

    def _list_triggers(self) -> bool:
        triggers = self._manager().list_triggers()
        if not triggers:
            print_info("No session triggers configured")
            return True
        for idx, trigger in enumerate(triggers):
            state = "enabled" if trigger.enabled else "disabled"
            label = trigger.name or trigger.event
            filters = []
            if trigger.session_types:
                filters.append("types=" + ",".join(trigger.session_types))
            if trigger.listeners:
                filters.append("listeners=" + ",".join(trigger.listeners))
            if trigger.platforms:
                filters.append("platforms=" + ",".join(trigger.platforms))
            filter_text = f" ({'; '.join(filters)})" if filters else ""
            print_info(f"[{idx}] {label} [{state}] event={trigger.event}{filter_text}")
            for action in trigger.actions:
                if action.type == "command":
                    print_info(f"     -> command: {action.command}")
                elif action.type == "module":
                    line = f"     -> module: {action.module_path}"
                    if action.options:
                        opts = ", ".join(f"{k}={v!r}" for k, v in action.options.items())
                        line += f"  (opts: {opts})"
                    print_info(line)
                elif action.type == "tag":
                    print_info(f"     -> tag: {action.tag}")
        return True

    def _module_options_from_cli(self, raw_opts: List[str]) -> Dict[str, Any]:
        options: Dict[str, Any] = {}
        for item in raw_opts or []:
            key, value = _parse_opt_pair(item)
            if not key:
                print_error(f"Invalid --opt/--set (expected NAME=VALUE): {item!r}")
                continue
            options[key] = _strip_quotes(value)
        return options

    def _add_trigger_args(self, args: List[str]) -> bool:
        try:
            parsed, unknown = self.add_parser.parse_known_args(args)
        except SystemExit:
            return False

        trailing, leftovers = _trailing_module_options(unknown)
        if leftovers:
            print_error(f"Unrecognized arguments: {' '.join(leftovers)}")
            print_info("Module options: --opt NAME=VALUE  or a trailing NAME=VALUE (e.g. message=KittySploit)")
            return False

        event = (parsed.event or "").strip().lower()
        if event not in SessionTriggerManager.EVENT_MAP:
            print_error(f"Invalid event. Choose from: {', '.join(SessionTriggerManager.EVENT_MAP.keys())}")
            return False

        module_options = self._module_options_from_cli(parsed.module_opts or [])
        module_options.update(trailing)
        if module_options and not parsed.module:
            print_error("Module options require --module")
            return False

        actions = []
        if parsed.command:
            actions.append(SessionTriggerAction(type="command", command=parsed.command.strip()))
        if parsed.module:
            actions.append(
                SessionTriggerAction(
                    type="module",
                    module_path=parsed.module.strip(),
                    options=module_options,
                )
            )
        if parsed.tag:
            actions.append(SessionTriggerAction(type="tag", tag=parsed.tag.strip()))
        if not actions:
            print_error("Specify at least one of --command, --module, or --tag")
            return False

        trigger = SessionTrigger(
            event=event,
            actions=actions,
            session_types=_split_csv(parsed.types or ""),
            listeners=_split_csv(parsed.listeners or ""),
            platforms=_split_csv(parsed.platforms or ""),
            enabled=True,
            name=(parsed.name or "").strip(),
        )
        self._manager().add_trigger(trigger)
        print_success(f"Added session trigger for {event}")
        return True

    def _remove_trigger_index(self, args: List[str]) -> bool:
        if not args:
            print_error("Usage: triggers remove <index>")
            return False
        try:
            index = int(args[0])
        except ValueError:
            print_error(f"Index must be an integer, got: {args[0]!r}")
            return False
        if args[1:]:
            print_error(f"Unexpected extra arguments: {' '.join(args[1:])}")
            return False
        if self._manager().remove_trigger(index):
            print_success(f"Removed trigger {index}")
            return True
        print_error(f"Trigger index {index} not found")
        return False

    def _set_enabled(self, enabled: bool) -> bool:
        count = self._manager().set_all_enabled(enabled)
        state = "enabled" if enabled else "disabled"
        print_success(f"All session triggers {state} ({count} rule(s))")
        return True