#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Bundle runner for React SPA scanners (distinct from the Next.js pack)."""

import shlex
from urllib.parse import urlparse

from kittysploit import *
from core.framework.plugin import ModuleArgumentParser, Plugin

# Heavy / off-pack tags: never pull these into the default React SPA runner.
_EXCLUDE_TAGS = frozenset({"nextjs", "dos"})
_DETECT_PATH = "scanner/http/react_detect"


class ReactPlugin(Plugin):
    """List or run modules tagged ``react`` (standalone SPA pack)."""

    __info__ = {
        "name": "react",
        "description": (
            "Bundle runner for React/Vite/CRA checks: list with -l, or run against "
            "one host with -t. Differs from plugin nextjs (App Router / RSC). "
            "Default run is scanner-only after a React fingerprint gate."
        ),
        "version": "1.1.0",
        "author": "KittySploit Team",
        "dependencies": [],
    }

    TAG = "react"

    def __init__(self, framework=None):
        super().__init__(framework)
        self._cached = []

    def _tags_list(self, info):
        if not info or "tags" not in info:
            return []
        t = info["tags"]
        if isinstance(t, list):
            return [str(x).lower() for x in t]
        return [str(t).lower()]

    def _path_kind(self, module_path: str) -> str:
        if "/auxiliary/" in module_path or module_path.startswith("auxiliary/"):
            return "auxiliary"
        if "/scanner/" in module_path or module_path.startswith("scanner/"):
            return "scanner"
        return "other"

    def _is_pack_eligible(self, module_path: str, tags) -> bool:
        tagset = {str(t).lower() for t in (tags or [])}
        if tagset & _EXCLUDE_TAGS:
            return False
        # Path hard-excludes (tag pollution / future modules)
        low = str(module_path or "").lower().replace("\\", "/")
        if "/dos/" in low or "nextjs" in low:
            return False
        return True

    def list_modules(
        self,
        auxiliary_only: bool,
        scanner_only: bool,
        *,
        include_excluded: bool = False,
    ):
        if not self.framework:
            print_error("Framework unavailable")
            return []

        out = []
        discovered = self.framework.module_loader.discover_modules()
        for module_path in discovered:
            if auxiliary_only and self._path_kind(module_path) != "auxiliary":
                continue
            if scanner_only and self._path_kind(module_path) != "scanner":
                continue
            try:
                mod = self.framework.module_loader.load_module(
                    module_path, load_only=True, framework=self.framework, silent=True
                )
                if not mod or not hasattr(mod, "__info__"):
                    continue
                tags = self._tags_list(mod.__info__)
                if self.TAG not in tags:
                    continue
                if not include_excluded and not self._is_pack_eligible(module_path, tags):
                    continue
                out.append((module_path, tags, mod.__info__.get("name", module_path)))
            except Exception:
                continue

        out.sort(key=lambda x: x[0])
        self._cached = out
        return out

    def _split_target(self, target: str, port: int, path: str, ssl_flag: bool):
        t = (target or "").strip()
        if not t:
            return t, port, path, ssl_flag
        low = t.lower()
        if not (low.startswith("http://") or low.startswith("https://")):
            return t, port, path, ssl_flag
        u = urlparse(t)
        host = u.hostname
        if not host:
            return t, port, path, ssl_flag
        new_port = u.port if u.port is not None else port
        p = (u.path or "").strip()
        frag = (u.fragment or "").strip()
        if p and p != "/":
            new_path = p
            if u.query:
                new_path += "?" + u.query
            if frag:
                new_path += "#" + frag
        else:
            new_path = path
        scheme = (u.scheme or "").lower()
        if scheme == "https":
            new_ssl = True
        elif scheme == "http":
            new_ssl = False
        else:
            new_ssl = ssl_flag
        return host, new_port, new_path, new_ssl

    def _apply_network_options(self, module, target: str, port: int, path: str, ssl_on: bool):
        if hasattr(module, "set_option"):
            if hasattr(module, "target"):
                module.set_option("target", target)
            elif hasattr(module, "rhost"):
                module.set_option("rhost", target)
            if hasattr(module, "port"):
                module.set_option("port", int(port))
            elif hasattr(module, "rport"):
                module.set_option("rport", int(port))
            if hasattr(module, "path"):
                module.set_option("path", path)
            if hasattr(module, "ssl"):
                module.set_option("ssl", ssl_on)

    def _run_one(self, module_path: str, target: str, port: int, path: str, ssl_on: bool):
        print_info(f"── {module_path} ──")
        module = self.framework.module_loader.load_module(
            module_path, load_only=False, framework=self.framework
        )
        if not module:
            print_error("  load failed")
            return False, None
        self._apply_network_options(module, target, port, path, ssl_on)
        if hasattr(module, "check_options") and not module.check_options():
            print_warning("  required options missing — skipped")
            return False, None
        if not hasattr(module, "run"):
            print_warning("  no run() method — skipped")
            return False, None
        result = module.run()
        stack = None
        try:
            info = getattr(module, "vulnerability_info", None) or {}
            stack = info.get("stack")
        except Exception:
            stack = None
        if result:
            print_success("  finished (returned True)")
        else:
            print_warning("  finished (returned False)")
        return bool(result), stack

    def _preflight_stack(self, target: str, port: int, path: str, ssl_on: bool):
        """Run react_detect probe; return (is_react_spa, stack_label, reason)."""
        try:
            from lib.scanner.http.react_probe import probe_react_stack

            probe_mod = self.framework.module_loader.load_module(
                _DETECT_PATH, load_only=False, framework=self.framework
            )
            if not probe_mod:
                return True, "unknown", ""  # fail open if detect missing
            self._apply_network_options(probe_mod, target, port, path, ssl_on)
            ok, reason, stack = probe_react_stack(probe_mod)
            return ok, stack, reason
        except Exception as exc:
            print_warning(f"Stack preflight failed ({exc}); continuing")
            return True, "unknown", ""

    def run(self, *args, **kwargs):
        parser = ModuleArgumentParser(description=self.description, prog="plugin run react")
        parser.add_argument("-l", "--list", action="store_true", dest="list", help="List modules tagged react")
        parser.add_argument("-n", "--dry-run", action="store_true", dest="dry_run", help="Print list without running")
        parser.add_argument("-t", "--target", dest="target", help="Target host, IP, or http(s) URL")
        parser.add_argument("--port", dest="port", type=int, default=3000, help="HTTP(S) port (default 3000)")
        parser.add_argument("--path", dest="path", default="/", help="Base path (default /)")
        parser.add_argument("-s", "--ssl", action="store_true", dest="ssl", help="Use HTTPS")
        parser.add_argument("--auxiliary-only", action="store_true", dest="auxiliary_only", help="Only auxiliary/")
        parser.add_argument("--scanner-only", action="store_true", dest="scanner_only", help="Only scanner/")
        parser.add_argument(
            "--full",
            action="store_true",
            dest="full",
            help="Include auxiliary modules (e.g. react_xss); default is scanner-only",
        )
        parser.add_argument(
            "--force",
            action="store_true",
            dest="force",
            help="Run pack even when React SPA fingerprint is missing / Next.js detected",
        )

        if not args or not args[0]:
            parser.print_help()
            print_info("Examples:  plugin run react -- -l")
            print_info("           plugin run react -- -t 127.0.0.1 --port 3000")
            print_info("           plugin run react -- -t https://app.example.com --scanner-only")
            print_info("           plugin run react -- -t https://app.example.com --full")
            print_info("Note: Next.js targets → plugin run nextjs")
            return True

        args_string = args[0] if isinstance(args[0], str) else " ".join(str(a) for a in args)
        try:
            pargs = parser.parse_args(shlex.split(args_string))
        except Exception as e:
            print_error(f"Arguments: {e}")
            parser.print_help()
            return False

        if pargs.auxiliary_only and pargs.scanner_only:
            print_error("Use at most one filter: --auxiliary-only or --scanner-only.")
            return False

        if pargs.target:
            h, po, pa, sl = self._split_target(pargs.target, pargs.port, pargs.path, pargs.ssl)
            pargs.target, pargs.port, pargs.path, pargs.ssl = h, po, pa, sl

        # Default -t run: scanner pack only (no XSS / DoS). --full or --auxiliary-only widens.
        scanner_only = pargs.scanner_only
        auxiliary_only = pargs.auxiliary_only
        if pargs.target and not pargs.list and not pargs.dry_run:
            if not auxiliary_only and not pargs.full and not scanner_only:
                scanner_only = True

        rows = self.list_modules(auxiliary_only, scanner_only)
        if not rows:
            print_warning("No modules with the 'react' tag (with current filters).")
            return True

        if pargs.list or pargs.dry_run or not pargs.target:
            print_success(f"Modules tagged '{self.TAG}' ({len(rows)}):\n")
            for module_path, tags, title in rows:
                print_status(f"  {module_path}")
                print_info(f"    {title}")
                print_info(f"    tags: {', '.join(tags)}")
            if not pargs.target and not pargs.list and not pargs.dry_run:
                print_warning("Specify -t <target> to run these modules (or use -l / -n).")
            return True

        # Stack gate before burning requests on sourcemap/env/xss probes
        print_info("Preflight: React SPA fingerprint…")
        is_react, stack, reason = self._preflight_stack(
            pargs.target, pargs.port, pargs.path, pargs.ssl
        )
        if stack == "nextjs" and not pargs.force:
            print_warning(
                "Next.js detected — skipping React SPA pack. "
                "Use: plugin run nextjs -- -t …  (or pass --force)"
            )
            return True
        if not is_react and not pargs.force:
            print_warning(
                f"No React SPA fingerprint ({reason or stack}). "
                "Skipping pack follow-ups (use --force to run anyway)."
            )
            return True
        if is_react:
            print_success(f"React SPA fingerprint OK (stack={stack})")

        # Prefer detect first in the run order, then the rest
        detect_rows = [r for r in rows if r[0].replace("\\", "/").endswith("react_detect")]
        other_rows = [r for r in rows if r not in detect_rows]
        ordered = detect_rows + other_rows

        print_success(
            f"Running {len(ordered)} React pack module(s) against "
            f"{pargs.target}:{pargs.port}{pargs.path} (ssl={pargs.ssl})\n"
        )
        ok = 0
        fail = 0
        for module_path, tags, title in ordered:
            try:
                result, _stack = self._run_one(
                    module_path, pargs.target, pargs.port, pargs.path, pargs.ssl
                )
                if result:
                    ok += 1
                else:
                    fail += 1
            except Exception as e:
                print_error(f"  error: {e}")
                fail += 1
        print_status(
            f"\nSummary: {ok} succeeded, {fail} failed or skipped out of {len(ordered)} module(s)."
        )
        return True
