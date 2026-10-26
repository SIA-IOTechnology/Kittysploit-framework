#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Vulners intelligence plugin and feed export for KittySploit."""

from __future__ import annotations

import json
import os
import shlex
from typing import Any, Dict, List, Optional, Sequence

from kittysploit import *
from core.output_handler import table_render_width
from core.service_secrets import SERVICE_VULNERS, get_service_secret_store
from lib.vulners.client import (
    PLUGIN_VERSION,
    VulnersClient,
    VulnersError,
    bulletin_display_title,
    exploits_query_for_cves,
    normalize_bulletin,
)
from lib.vulners.feed import build_module_bulletin, iter_feed_bulletins


class VulnersPlugin(Plugin):
    __info__ = {
        "name": "vulners",
        "description": "Query Vulners and export the KittySploit module feed",
        "version": PLUGIN_VERSION,
        "author": "KittySploit Team",
        "dependencies": ["requests"],
    }

    def __init__(self, framework=None):
        super().__init__(framework)

    @staticmethod
    def _parse_tokens(tokens: List[str]) -> tuple[Dict[str, Any], List[str]]:
        """Parse flags; ModuleArgumentParser does not support positional args."""
        opts: Dict[str, Any] = {}
        pos: List[str] = []
        i = 0
        while i < len(tokens):
            t = tokens[i]
            if t in ("-h", "--help"):
                opts["help"] = True
                i += 1
                continue
            if t == "--limit" and i + 1 < len(tokens):
                try:
                    opts["limit"] = int(tokens[i + 1])
                except ValueError:
                    opts["limit"] = tokens[i + 1]
                i += 2
                continue
            if t == "--references":
                opts["references"] = True
                i += 1
                continue
            if t == "--exploits":
                opts["exploits"] = True
                i += 1
                continue
            if t == "--type" and i + 1 < len(tokens):
                opts["ref_type"] = tokens[i + 1]
                i += 2
                continue
            if t in ("-o", "--output") and i + 1 < len(tokens):
                opts["output"] = tokens[i + 1]
                i += 2
                continue
            if t == "--module" and i + 1 < len(tokens):
                opts["module"] = tokens[i + 1]
                i += 2
                continue
            if t == "--jsonl":
                opts["jsonl"] = True
                i += 1
                continue
            if t == "--os" and i + 1 < len(tokens):
                opts["os_name"] = tokens[i + 1]
                i += 2
                continue
            if t == "--version" and i + 1 < len(tokens):
                opts["os_version"] = tokens[i + 1]
                i += 2
                continue
            if t == "--packages" and i + 1 < len(tokens):
                opts["packages_file"] = tokens[i + 1]
                i += 2
                continue
            if t.startswith("-"):
                i += 1
                continue
            pos.append(t)
            i += 1
        return opts, pos

    def _resolve_api_key(self) -> str:
        if self.framework is not None:
            try:
                row = get_service_secret_store(self.framework).get(SERVICE_VULNERS)
                if row and str(row.get("secret") or "").strip():
                    return str(row["secret"]).strip()
            except Exception:
                pass
        return str(os.environ.get("VULNERS_API_KEY") or "").strip()

    def _client(self) -> VulnersClient:
        return VulnersClient(self._resolve_api_key())

    @staticmethod
    def _collect_audit_cves(audit_payload: Dict[str, Any]) -> List[str]:
        found: List[str] = []
        seen = set()

        def add_cve(value: Any) -> None:
            token = str(value or "").strip().upper()
            if token.startswith("CVE-") and token not in seen:
                seen.add(token)
                found.append(token)

        for key in ("cvelist", "cves"):
            raw = audit_payload.get(key)
            if isinstance(raw, list):
                for item in raw:
                    add_cve(item)

        for issue in audit_payload.get("issues") or []:
            if not isinstance(issue, dict):
                continue
            for item in issue.get("cvelist") or issue.get("cves") or []:
                add_cve(item)
            for adv in issue.get("applicableAdvisories") or []:
                if isinstance(adv, dict):
                    for item in adv.get("cvelist") or []:
                        add_cve(item)
        return found

    @staticmethod
    def _cves_from_doc(doc: Dict[str, Any]) -> List[str]:
        out: List[str] = []
        seen = set()
        for item in doc.get("cvelist") or []:
            token = str(item or "").strip().upper()
            if token.startswith("CVE-") and token not in seen:
                seen.add(token)
                out.append(token)
        return out

    def _print_bulletin_table(self, rows: List[List[str]]) -> None:
        headers = ["ID", "Type", "Title"]
        kwargs = {
            "max_width": 100,
            "expand_to_terminal": True,
            "column_min_widths": {"Type": 12, "Title": 30},
            "protect_full_width_headers": ("ID",),
            "wrap_extra_headers": ("Title",),
        }
        width = table_render_width(headers, rows, **kwargs) or 100
        print_info("=" * width)
        print_table(headers, rows, **kwargs)
        print_info("=" * width)

    def _print_exploit_hits(self, cves: Sequence[str], limit: int) -> None:
        if not cves:
            print_warning("No CVE ids available for exploit lookup.")
            return
        client = self._client()
        query = exploits_query_for_cves(cves)
        print_info(f"Exploit query: {query}")
        items = list(client.iter_search(query, limit=limit))
        if not items:
            print_warning("No public exploits matched the CVE list.")
            return
        rows = []
        for doc in items:
            rows.append(
                [
                    str(doc.get("id") or ""),
                    str(doc.get("type") or ""),
                    bulletin_display_title(doc),
                ]
            )
        self._print_bulletin_table(rows)
        print_info(f"Matched {len(items)} exploit bulletins.")

    def _cmd_key(self, tokens: List[str]) -> bool:
        if not tokens:
            print_error("Usage: plugin run vulners key set <api-key>")
            return False
        action = tokens[0].lower()
        if action != "set" or len(tokens) < 2:
            print_error("Usage: plugin run vulners key set <api-key>")
            return False
        secret = "".join(part.strip() for part in tokens[1:] if part.strip())
        if not secret:
            print_error("API key is empty.")
            return False
        if self.framework is None:
            print_error("Framework is not available.")
            return False
        try:
            get_service_secret_store(self.framework).set(SERVICE_VULNERS, secret)
        except Exception as exc:
            print_error(f"Could not store Vulners API key: {exc}")
            return False
        print_success("Vulners API key stored in encrypted service secrets.")
        return True

    def _cmd_search(self, tokens: List[str]) -> bool:
        opts, pos = self._parse_tokens(tokens)
        if opts.get("help") or not pos:
            print_info("Usage: plugin run vulners search <lucene-query> [--limit N]")
            return True
        query = " ".join(pos).strip()
        limit = int(opts.get("limit") or 20)
        client = self._client()
        items = list(client.iter_search(query, limit=max(1, limit)))
        rows = [
            [str(d.get("id") or ""), str(d.get("type") or ""), bulletin_display_title(d)]
            for d in items
        ]
        self._print_bulletin_table(rows)
        print_info(f"Showing {len(items)} result(s).")
        return True

    def _cmd_cve(self, tokens: List[str]) -> bool:
        opts, pos = self._parse_tokens(tokens)
        if opts.get("help") or not pos:
            print_info(
                "Usage: plugin run vulners cve <CVE> [--references] [--type TYPE] [--limit N]"
            )
            return True

        cve_id = str(pos[0]).strip().upper()
        client = self._client()
        doc_payload = client.search_by_id(cve_id, references=False)
        documents = doc_payload.get("documents") or doc_payload.get("search") or doc_payload
        if isinstance(documents, dict):
            doc = normalize_bulletin(documents.get(cve_id) or documents)
        elif isinstance(documents, list) and documents:
            doc = normalize_bulletin(documents[0])
        else:
            doc = normalize_bulletin(doc_payload)

        print_info(f"ID: {doc.get('id', cve_id)}")
        print_info(f"Title: {bulletin_display_title(doc)}")
        if doc.get("published"):
            print_info(f"Published: {doc.get('published')}")
        if doc.get("modified"):
            print_info(f"Modified: {doc.get('modified')}")

        if not opts.get("references"):
            return True

        ref_limit = int(opts.get("limit") or 50)
        rows: List[List[str]] = []
        for ref in client.iter_references(cve_id, ref_type=opts.get("ref_type"), page_size=100):
            if ref_limit and len(rows) >= ref_limit:
                break
            rows.append(
                [
                    str(ref.get("id") or ""),
                    str(ref.get("type") or ""),
                    bulletin_display_title(ref),
                ]
            )
        if not rows:
            print_warning("No related references returned.")
            return True
        self._print_bulletin_table(rows)
        print_info(f"Showing {len(rows)} reference(s) (paged via /api/v4/search/references).")
        return True

    def _cmd_id(self, tokens: List[str]) -> bool:
        opts, pos = self._parse_tokens(tokens)
        if opts.get("help") or not pos:
            print_info("Usage: plugin run vulners id <KS:...> [--exploits] [--limit N]")
            return True
        bulletin_id = pos[0]

        client = self._client()
        payload = client.search_by_id(bulletin_id, references=False)
        documents = payload.get("documents") or payload
        doc: Dict[str, Any] = {}
        if isinstance(documents, dict):
            doc = normalize_bulletin(documents.get(bulletin_id) or next(iter(documents.values()), {}))
        else:
            doc = normalize_bulletin(documents)

        print_info(f"ID: {doc.get('id', bulletin_id)}")
        print_info(f"Title: {bulletin_display_title(doc)}")
        if doc.get("href"):
            print_info(f"Href: {doc.get('href')}")
        if doc.get("cvelist"):
            print_info(f"CVEs: {', '.join(str(c) for c in doc.get('cvelist') or [])}")

        if opts.get("exploits"):
            ref_limit = int(opts.get("limit") or 25)
            self._print_exploit_hits(self._cves_from_doc(doc), limit=max(1, ref_limit))
        return True

    def _cmd_audit(self, tokens: List[str]) -> bool:
        opts, pos = self._parse_tokens(tokens)
        if opts.get("help") or not pos:
            print_info(
                "Usage: plugin run vulners audit linux|library --packages <file> "
                "[--os NAME --version VER] [--exploits] [--limit N]"
            )
            return True
        mode = pos[0].lower()
        if mode not in ("linux", "library"):
            print_error("Audit mode must be 'linux' or 'library'.")
            return False
        packages_file = opts.get("packages_file")
        if not packages_file or not os.path.isfile(packages_file):
            print_error("--packages must point to a file with one package per line.")
            return False
        with open(packages_file, "r", encoding="utf-8", errors="ignore") as fh:
            packages = [line.strip() for line in fh if line.strip() and not line.startswith("#")]
        if not packages:
            print_error("Package list is empty.")
            return False

        client = self._client()
        try:
            if mode == "linux":
                if not opts.get("os_name") or not opts.get("os_version"):
                    print_error("linux audit requires --os and --version.")
                    return False
                result = client.linux_audit(
                    str(opts["os_name"]),
                    str(opts["os_version"]),
                    packages,
                )
            else:
                result = client.library_audit(packages)
        except VulnersError as exc:
            print_error(str(exc))
            return False

        issues = result.get("issues") or []
        print_info(f"Audit returned {len(issues)} issue(s).")
        cves = self._collect_audit_cves(result)
        if cves:
            print_info(f"Top CVEs: {', '.join(cves)}")
        if opts.get("exploits"):
            ref_limit = int(opts.get("limit") or 25)
            self._print_exploit_hits(cves, limit=max(1, ref_limit))
        return True

    def _cmd_feed(self, tokens: List[str]) -> bool:
        opts, pos = self._parse_tokens(tokens)
        if opts.get("help") or not pos or pos[0].lower() != "export":
            print_info(
                "Usage: plugin run vulners feed export [-o file.json] [--jsonl] [--module path]"
            )
            return True
        if not self.framework:
            print_error("Framework is not available.")
            return False

        loader = self.framework.module_loader
        discovered = loader.discover_modules()
        bulletins: List[Dict[str, Any]] = []
        if opts.get("module"):
            module_path = str(opts["module"]).replace("\\", "/").strip("/")
            file_path = discovered.get(module_path)
            if not file_path:
                print_error(f"Unknown module: {module_path}")
                return False
            bulletins = [build_module_bulletin(module_path, file_path)]
        else:
            bulletins = list(iter_feed_bulletins(discovered))

        out_path = opts.get("output")
        if out_path:
            with open(out_path, "w", encoding="utf-8") as fh:
                if opts.get("jsonl"):
                    for item in bulletins:
                        fh.write(json.dumps(item, ensure_ascii=False) + "\n")
                else:
                    json.dump(bulletins, fh, ensure_ascii=False, indent=2)
            print_success(f"Wrote {len(bulletins)} bulletin(s) to {out_path}")
        else:
            preview = bulletins[:1]
            print_info(json.dumps(preview, ensure_ascii=False, indent=2))
            print_info(f"Total bulletins: {len(bulletins)} (use -o to write file)")
        return True

    def _print_help(self) -> None:
        print_info("Vulners plugin — query Vulners and export the KittySploit feed")
        print_info("")
        print_info("Usage:")
        print_info("  plugin run vulners key set <api-key>")
        print_info("  plugin run vulners search <lucene-query> [--limit N]")
        print_info("  plugin run vulners cve <CVE> [--references] [--type TYPE] [--limit N]")
        print_info("  plugin run vulners id KS:EXPLOITS-LINUX-HTTP-APACHE_CVE_2021_41773_RCE [--exploits]")
        print_info("  plugin run vulners audit linux --os ubuntu --version 22.04 --packages pkgs.txt [--exploits]")
        print_info("  plugin run vulners audit library --packages pkgs.txt [--exploits]")
        print_info("  plugin run vulners feed export [-o feed.json] [--jsonl] [--module path]")
        print_info("")
        print_info("API key: encrypted store (vulners) or VULNERS_API_KEY environment variable.")

    def run(self, *args, **kwargs):
        tokens = shlex.split(args[0]) if args and args[0] else []
        if not tokens:
            self._print_help()
            return True

        command = tokens[0].lower()
        rest = tokens[1:]
        if command in ("feed", "key", "help", "-h", "--help"):
            try:
                if command == "feed":
                    return self._cmd_feed(rest)
                if command == "key":
                    return self._cmd_key(rest)
                self._print_help()
                return True
            except Exception as exc:
                print_error(f"Vulners plugin error: {exc}")
                return False

        if not self._resolve_api_key():
            print_error("Missing Vulners API key. Use: plugin run vulners key set <key>")
            print_info("Or set VULNERS_API_KEY in the environment.")
            return False

        try:
            if command == "search":
                return self._cmd_search(rest)
            if command == "cve":
                return self._cmd_cve(rest)
            if command == "id":
                return self._cmd_id(rest)
            if command == "audit":
                return self._cmd_audit(rest)
            if command in ("help", "-h", "--help"):
                self._print_help()
                return True
            print_error(f"Unknown vulners command: {command}")
            self._print_help()
            return False
        except VulnersError as exc:
            print_error(str(exc))
            return False
        except Exception as exc:
            print_error(f"Vulners plugin error: {exc}")
            return False
