#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Manage automatic session lifecycle triggers."""

import argparse
from interfaces.command_system.base_command import BaseCommand
from core.output_handler import print_info, print_success, print_error, print_warning
from core.session_triggers import SessionTrigger, SessionTriggerAction, SessionTriggerManager


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
    list                         List configured session triggers
    add --event <event> ...      Add a runtime trigger
    remove <index>               Remove trigger by index (from list)
    enable                       Enable trigger processing (runtime)
    disable                      Disable trigger processing (runtime)

Events:
    session.created              New implant session
    session.reconnected          Durable session came back online
    session.closed               Session removed or disconnected

Examples:
    triggers list
    triggers add --event session.created --command sysinfo
    triggers add --event session.created --tag initial --types meterpreter
    triggers remove 0
        """

    def __init__(self, framework, session, output_handler):
        super().__init__(framework, session, output_handler)
        self.parser = self._create_parser()

    def _manager(self) -> SessionTriggerManager:
        mgr = getattr(self.framework, "session_trigger_manager", None)
        if mgr is None:
            raise RuntimeError("Session trigger manager is not initialized")
        return mgr

    def _create_parser(self) -> argparse.ArgumentParser:
        parser = argparse.ArgumentParser(prog="triggers", add_help=False)
        parser.add_argument("subcommand", nargs="?", default="list")
        parser.add_argument("index", nargs="?", type=int)
        parser.add_argument("--event", help="Trigger event name")
        parser.add_argument("--command", help="Shell/meterpreter command to run")
        parser.add_argument("--module", help="Post module path to run")
        parser.add_argument("--tag", help="Tag to apply to the session")
        parser.add_argument("--types", help="Comma-separated session types filter")
        parser.add_argument("--listeners", help="Comma-separated listener module paths filter")
        parser.add_argument("--name", help="Optional trigger label")
        return parser

    def execute(self, args, **kwargs) -> bool:
        try:
            parsed = self.parser.parse_args(args)
        except SystemExit:
            return True

        sub = (parsed.subcommand or "list").lower()
        try:
            if sub in ("help", "-h", "--help"):
                print_info(self.help_text)
                return True
            if sub == "list":
                return self._list_triggers()
            if sub == "add":
                return self._add_trigger(parsed)
            if sub == "remove":
                return self._remove_trigger(parsed)
            if sub == "enable":
                return self._set_enabled(True)
            if sub == "disable":
                return self._set_enabled(False)
            print_error(f"Unknown subcommand: {sub}")
            return False
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
            filter_text = f" ({'; '.join(filters)})" if filters else ""
            print_info(f"[{idx}] {label} [{state}] event={trigger.event}{filter_text}")
            for action in trigger.actions:
                if action.type == "command":
                    print_info(f"     -> command: {action.command}")
                elif action.type == "module":
                    print_info(f"     -> module: {action.module_path}")
                elif action.type == "tag":
                    print_info(f"     -> tag: {action.tag}")
        return True

    def _add_trigger(self, parsed) -> bool:
        event = (parsed.event or "").strip().lower()
        if event not in SessionTriggerManager.EVENT_MAP:
            print_error(f"Invalid event. Choose from: {', '.join(SessionTriggerManager.EVENT_MAP.keys())}")
            return False

        actions = []
        if parsed.command:
            actions.append(SessionTriggerAction(type="command", command=parsed.command.strip()))
        if parsed.module:
            actions.append(SessionTriggerAction(type="module", module_path=parsed.module.strip()))
        if parsed.tag:
            actions.append(SessionTriggerAction(type="tag", tag=parsed.tag.strip()))
        if not actions:
            print_error("Specify at least one of --command, --module, or --tag")
            return False

        trigger = SessionTrigger(
            event=event,
            actions=actions,
            session_types=[x.strip() for x in (parsed.types or "").split(",") if x.strip()],
            listeners=[x.strip() for x in (parsed.listeners or "").split(",") if x.strip()],
            enabled=True,
            name=(parsed.name or "").strip(),
        )
        self._manager().add_trigger(trigger)
        print_success(f"Added session trigger for {event}")
        return True

    def _remove_trigger(self, parsed) -> bool:
        if parsed.index is None:
            print_error("Usage: triggers remove <index>")
            return False
        if self._manager().remove_trigger(parsed.index):
            print_success(f"Removed trigger {parsed.index}")
            return True
        print_error(f"Trigger index {parsed.index} not found")
        return False

    def _set_enabled(self, enabled: bool) -> bool:
        count = self._manager().set_all_enabled(enabled)
        state = "enabled" if enabled else "disabled"
        print_success(f"All session triggers {state} ({count} rule(s))")
        return True
