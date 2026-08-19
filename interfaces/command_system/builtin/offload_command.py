#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Manage edge offload HTTP hop listeners."""

import argparse

from interfaces.command_system.base_command import BaseCommand
from core.output_handler import print_error, print_info, print_success


class OffloadCommand(BaseCommand):
    @property
    def name(self) -> str:
        return "offload"

    @property
    def description(self) -> str:
        return "Register and run edge offload hop listeners"

    @property
    def usage(self) -> str:
        return "offload [list|add|start|stop|remove] [options]"

    def _manager(self):
        mgr = getattr(self.framework, "offload_listener_manager", None)
        if mgr is None:
            raise RuntimeError("Offload listener manager is not initialized")
        return mgr

    def execute(self, args, **kwargs) -> bool:
        parser = argparse.ArgumentParser(prog="offload", add_help=False)
        parser.add_argument("subcommand", nargs="?", default="list")
        parser.add_argument("id", nargs="?")
        parser.add_argument("--bind-host", default="0.0.0.0")
        parser.add_argument("--bind-port", type=int, default=8080)
        parser.add_argument("--upstream", default="", help="Teamserver URL host:port")
        parser.add_argument("--token", default="")
        try:
            parsed = parser.parse_args(args)
        except SystemExit:
            return True

        sub = (parsed.subcommand or "list").lower()
        mgr = self._manager()
        try:
            if sub == "list":
                specs = mgr.list_specs()
                if not specs:
                    print_info("No offload listeners registered")
                    return True
                for spec in specs:
                    running = spec.listener_id in getattr(mgr, "_servers", {})
                    state = "running" if running else "stopped"
                    print_info(
                        f"{spec.listener_id} [{state}] {spec.bind_host}:{spec.bind_port} -> {spec.upstream}"
                    )
                return True
            if sub == "add":
                if not parsed.upstream:
                    print_error("Usage: offload add --upstream host:port [--bind-port N]")
                    return False
                lid = mgr.register(parsed.bind_host, parsed.bind_port, parsed.upstream, token=parsed.token)
                print_success(f"Registered offload listener {lid}")
                return True
            if sub == "start":
                if not parsed.id:
                    print_error("Usage: offload start <id>")
                    return False
                if mgr.start(parsed.id):
                    print_success(f"Started offload listener {parsed.id}")
                    return True
                print_error(f"Could not start offload listener {parsed.id}")
                return False
            if sub == "stop":
                if not parsed.id:
                    print_error("Usage: offload stop <id>")
                    return False
                if mgr.stop(parsed.id):
                    print_success(f"Stopped offload listener {parsed.id}")
                    return True
                print_error(f"Offload listener {parsed.id} not running")
                return False
            if sub == "remove":
                if not parsed.id:
                    print_error("Usage: offload remove <id>")
                    return False
                if mgr.unregister(parsed.id):
                    print_success(f"Removed offload listener {parsed.id}")
                    return True
                print_error(f"Offload listener {parsed.id} not found")
                return False
            print_error(f"Unknown subcommand: {sub}")
            return False
        except Exception as exc:
            print_error(f"Offload command failed: {exc}")
            return False
