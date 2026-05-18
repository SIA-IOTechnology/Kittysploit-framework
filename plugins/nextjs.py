#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re
import shlex
from urllib.parse import urlparse

from kittysploit import *
from core.framework.plugin import ModuleArgumentParser, Plugin

_GHSA_RE = re.compile(r"GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}", re.I)


class NextjsPlugin(Plugin):
    """Run every Next.js security module in one go, or list them first."""

    __info__ = {
        "name": "nextjs",
        "description": (
            "Bundle runner for Next.js checks: list them with -l, or run them all against one host with -t."
        ),
        "version": "1.0.0",
        "author": "KittySploit Team",
        "dependencies": [],
    }

    TAG = "nextjs"

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

    def list_modules(self, auxiliary_only: bool, scanner_only: bool):
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
                out.append((module_path, tags, mod.__info__.get("name", module_path)))
            except Exception:
                continue

        out.sort(key=lambda x: x[0])
        self._cached = out
        return out

    def _split_target(self, target: str, port: int, path: str, ssl_flag: bool):
        """If `-t` is a full URL, return hostname, port, path, and ssl from the URL."""
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

    def _normalize_cve(self, cve):
        s = str(cve or "").strip().upper()
        return s or None

    def _ghsa_set_from_info(self, info):
        if not info:
            return set()
        parts = []
        for ref in info.get("references") or []:
            parts.append(str(ref))
        for k in ("name", "description"):
            v = info.get(k)
            if isinstance(v, str):
                parts.append(v)
        blob = " ".join(parts)
        return {m.group(0).upper() for m in _GHSA_RE.finditer(blob)}

    def _build_auxiliary_index(self):
        """Next.js-tagged modules under auxiliary/ (metadata for CVE/GHSA linking)."""
        idx = []
        if not self.framework:
            return idx
        for module_path in self.framework.module_loader.discover_modules():
            if self._path_kind(module_path) != "auxiliary":
                continue
            try:
                mod = self.framework.module_loader.load_module(
                    module_path, load_only=True, framework=self.framework, silent=True
                )
                if not mod or not hasattr(mod, "__info__"):
                    continue
                inf = mod.__info__
                if self.TAG not in self._tags_list(inf):
                    continue
                idx.append(
                    {
                        "path": module_path,
                        "cve": self._normalize_cve(inf.get("cve")),
                        "ghsas": self._ghsa_set_from_info(inf),
                        "title": inf.get("name", module_path),
                    }
                )
            except Exception:
                continue
        idx.sort(key=lambda r: r["path"])
        return idx

    def _linked_auxiliaries(self, scanner_info):
        """Auxiliary modules that share the same CVE and/or GitHub advisory id as the scanner."""
        cve = self._normalize_cve((scanner_info or {}).get("cve"))
        scan_gh = self._ghsa_set_from_info(scanner_info or {})
        hits = []
        for row in getattr(self, "_auxiliary_index", []) or []:
            if cve and row["cve"] == cve:
                hits.append(row)
            elif scan_gh and row["ghsas"] & scan_gh:
                hits.append(row)
        by_path = {row["path"]: row for row in hits}
        out = list(by_path.values())
        out.sort(key=lambda r: (0 if "/dos/" in r["path"] else 1, r["path"]))
        return out

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

    def run(self, *args, **kwargs):
        parser = ModuleArgumentParser(description=self.description, prog="plugin run nextjs")
        parser.add_argument("-l", "--list", action="store_true", dest="list", help="List all modules tagged nextjs")
        parser.add_argument("-n", "--dry-run", action="store_true", dest="dry_run", help="Print the list without running modules")
        parser.add_argument(
            "-t",
            "--target",
            dest="target",
            help="Target host, IP, or full http(s) URL (required to run modules)",
        )
        parser.add_argument("--port", dest="port", type=int, default=3000, help="HTTP(S) port (default 3000)")
        parser.add_argument("--path", dest="path", default="/", help="Base path (default /)")
        parser.add_argument("-s", "--ssl", action="store_true", dest="ssl", help="Use HTTPS")
        parser.add_argument(
            "--auxiliary-only",
            action="store_true",
            dest="auxiliary_only",
            help="Only modules under auxiliary/ paths",
        )
        parser.add_argument(
            "--scanner-only",
            action="store_true",
            dest="scanner_only",
            help="Only modules under scanner/ paths",
        )

        if not args or not args[0]:
            parser.print_help()
            print_info("Examples:  plugin run nextjs -- -l")
            print_info("           plugin run nextjs -- -t 127.0.0.1 --port 3000 --path /")
            return True

        args_string = args[0] if isinstance(args[0], str) else " ".join(str(a) for a in args)
        try:
            pargs = parser.parse_args(shlex.split(args_string))
        except Exception as e:
            print_error(f"Arguments: {e}")
            parser.print_help()
            return False

        if getattr(pargs, "help", False):
            parser.print_help()
            return True

        if pargs.auxiliary_only and pargs.scanner_only:
            print_error("Use at most one filter: --auxiliary-only or --scanner-only.")
            return False

        if pargs.target:
            h, po, pa, sl = self._split_target(pargs.target, pargs.port, pargs.path, pargs.ssl)
            pargs.target, pargs.port, pargs.path, pargs.ssl = h, po, pa, sl

        rows = self.list_modules(pargs.auxiliary_only, pargs.scanner_only)
        if not rows:
            print_warning("No modules with the 'nextjs' tag (with current filters).")
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

        print_success(f"Running {len(rows)} module(s) sequentially against {pargs.target}:{pargs.port}{pargs.path} (ssl={pargs.ssl})\n")
        self._auxiliary_index = self._build_auxiliary_index()
        ok = 0
        fail = 0
        for module_path, tags, title in rows:
            try:
                print_info(f"── {module_path} ──")
                module = self.framework.module_loader.load_module(
                    module_path, load_only=False, framework=self.framework
                )
                if not module:
                    print_error("  load failed")
                    fail += 1
                    continue
                self._apply_network_options(module, pargs.target, pargs.port, pargs.path, pargs.ssl)
                if hasattr(module, "check_options") and not module.check_options():
                    print_warning("  required options missing — skipped")
                    fail += 1
                    continue
                if not hasattr(module, "run"):
                    print_warning("  no run() method — skipped")
                    fail += 1
                    continue
                result = module.run()
                if result:
                    print_success("  finished (returned True)")
                    linked = self._linked_auxiliaries(getattr(module, "__info__", None))
                    if linked:
                        print_info("  Associated auxiliary module(s) (same target options):")
                        for row in linked:
                            print_status(f"    use {row['path']}")
                            print_info(f"      {row['title']}")
                    ok += 1
                else:
                    print_warning(f"  finished (returned False)")
                    fail += 1
            except Exception as e:
                print_error(f"  error: {e}")
                fail += 1
        print_status(f"\nSummary: {ok} succeeded, {fail} failed or skipped out of {len(rows)} module(s).")
        return True
