#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import shlex

from kittysploit import *
from core.output_handler import table_render_width
from core.utils.module_static_metadata import parse_static_module_info

# Router exploitation pack — RCE / backdoor / command injection only.
_ROUTER_EXPLOIT_PREFIXES = (
    "exploits/linux/router/",
    "exploits/linux/udp/",
    "exploits/linux/tcp/",
)

# Other Linux exploit trees: require IoT/router scope + active exploitation tags.
_ROUTER_FILTERED_PREFIXES = (
    "exploits/linux/http/",
    "exploits/linux/ssh/",
    "exploits/linux/misc/",
)

_DEVICE_TAGS = frozenset({"router", "iot", "embedded"})
_EXPLOIT_TAGS = frozenset({"rce", "backdoor", "cmdi", "shell"})


class RouterPlugin(Plugin):
    """List and run modules that exploit SOHO / IoT routers."""

    __info__ = {
        "name": "router",
        "description": (
            "Bundle runner for router exploitation modules (RCE, backdoor, command "
            "injection). List with -l, or run all against one target with -t."
        ),
        "version": "1.2.1",
        "author": "KittySploit Team",
        "dependencies": [],
    }

    def __init__(self, framework=None):
        super().__init__(framework)
        self.router_modules = []

    @staticmethod
    def _tags_from_info(info: dict) -> set[str]:
        if not info:
            return set()
        raw = info.get("tags") or info.get("plugins") or []
        if isinstance(raw, str):
            return {raw.lower()} if raw.strip() else set()
        return {str(tag).lower() for tag in raw if str(tag).strip()}

    @classmethod
    def is_router_exploit(cls, module_path: str, info: dict) -> bool:
        """Return True when the module can actively exploit a router device."""
        path = (module_path or "").replace("\\", "/")
        if not path.startswith("exploits/"):
            return False

        if any(path.startswith(prefix) for prefix in _ROUTER_EXPLOIT_PREFIXES):
            return True

        if not any(path.startswith(prefix) for prefix in _ROUTER_FILTERED_PREFIXES):
            return False

        tags = cls._tags_from_info(info)
        return bool(tags & _DEVICE_TAGS and tags & _EXPLOIT_TAGS)

    @staticmethod
    def _proto_from_path(module_path: str) -> str:
        path = (module_path or "").replace("\\", "/")
        parts = path.split("/")
        if len(parts) >= 3 and parts[0] == "exploits" and parts[1] == "linux":
            return parts[2]
        return "—"

    @staticmethod
    def _one_line(value) -> str:
        return str(value or "").replace("\n", " ").strip()

    def list_modules(self):
        """Discover router exploit modules from static metadata (no full-tree import)."""
        if not self.framework:
            print_error("Framework not available")
            return []

        discovered = self.framework.module_loader.discover_modules()
        entries = []

        for module_path, file_path in discovered.items():
            if not file_path or not os.path.isfile(file_path):
                continue
            try:
                info = parse_static_module_info(file_path)
            except OSError:
                continue
            if not self.is_router_exploit(module_path, info):
                continue
            tags = info.get("tags") or []
            name = info.get("name") or module_path
            description = info.get("description") or ""
            entries.append((module_path, tags, name, description))

        self.router_modules = sorted(entries, key=lambda row: row[0])
        return self.router_modules

    def _print_module_table(self, router_list):
        rows = []
        for module_path, _tags, name, description in router_list:
            rows.append([
                module_path,
                self._proto_from_path(module_path),
                self._one_line(name),
                self._one_line(description),
            ])

        headers = ["Path", "Proto", "Name", "Description"]
        table_kwargs = {
            "max_width": 80,
            "expand_to_terminal": True,
            "column_min_widths": {"Proto": 6, "Name": 22, "Description": 28},
            "protect_full_width_headers": ("Path",),
            "wrap_extra_headers": ("Name", "Description"),
            "prefer_single_line": True,
        }
        frame_width = table_render_width(headers, rows, **table_kwargs) or 80
        print_info("=" * frame_width)
        print_table(headers, rows, **table_kwargs)
        print_info("=" * frame_width)

    def _load_router_module(self, module_path: str, *, load_only: bool = True):
        return self.framework.module_loader.load_module(
            module_path,
            load_only=load_only,
            framework=self.framework,
            silent=True,
        )

    def run(self, *args, **kwargs):
        parser = ModuleArgumentParser(description=self.__doc__, prog="router")
        parser.add_argument(
            "-l", "--list", action="store_true", dest="list",
            help="List router exploitation modules (RCE / backdoor / cmdi)",
        )
        parser.add_argument(
            "-t", "--target", dest="target",
            help="Target IP/hostname for all router exploit modules", metavar="<target>",
        )

        if not args or not args[0]:
            parser.print_help()
            return True

        try:
            args_string = args[0] if isinstance(args[0], str) else " ".join(args)
            pargs = parser.parse_args(shlex.split(args_string))

            if getattr(pargs, "help", False):
                parser.print_help()
                return True

            if pargs.list:
                router_list = self.list_modules()

                if not router_list:
                    print_warning("No router exploitation modules found")
                    return True

                print_success(f"Router exploitation modules ({len(router_list)})")
                print_empty()
                self._print_module_table(router_list)
                print_empty()
                print_info("Run against a target: plugin run router -- -t <host>")
                return True

            if pargs.target:
                print_success(f"Running router exploits against target: {pargs.target}")
                router_list = self.list_modules()

                if not router_list:
                    print_warning("No router exploitation modules found")
                    return True

                for module_path, _tags, _name, _description in router_list:
                    try:
                        print_info(f"\nStarting module: {module_path}")
                        module = self._load_router_module(module_path, load_only=False)
                        if not module:
                            print_error(f"Failed to load module {module_path}")
                            continue

                        if hasattr(module, "rhost"):
                            module.set_option("rhost", pargs.target)
                        elif hasattr(module, "target"):
                            module.set_option("target", pargs.target)

                        if hasattr(module, "check_options") and not module.check_options():
                            print_warning(
                                f"  Module {module_path} is missing required options, skipping..."
                            )
                            continue

                        if hasattr(module, "run"):
                            result = module.run()
                            if result:
                                print_success(f"Module {module_path} executed successfully")
                            else:
                                print_warning(f"Module {module_path} execution returned False")
                        else:
                            print_warning(f"Module {module_path} does not have a run() method")
                    except Exception as exc:
                        print_error(f"  Error starting module {module_path}: {exc}")

                return True

            parser.print_help()
            return True

        except Exception as exc:
            print_error(f"An error occurred: {exc}")
            import traceback
            print_debug(traceback.format_exc())
            return False
