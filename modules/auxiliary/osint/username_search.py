#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Enumerate social-media accounts for a username via the WhatsMyName catalog."""

from __future__ import annotations

import json
import os

from kittysploit import *

from lib.osint.username_search import search_username_accounts_sync


class Module(Auxiliary):
    __info__ = {
        "name": "Username Search",
        "author": ["KittySploit Team"],
        "description": (
            "Check social platforms for likely username existence using the cached "
            "WhatsMyName site catalog (with trusted-site filtering)."
        ),
        "tags": ["osint", "identity", "username", "social", "passive"],
        "agent": {
            "risk": "passive",
            "effects": ["osint_lookup"],
            "expected_requests": 25,
            "reversible": True,
            "approval_required": False,
            "produces": ["social_profiles", "profile_urls"],
        },
    }

    username = OptString("", "Username to search across social platforms", required=True)
    min_username_length = OptString(
        "4",
        "Skip usernames shorter than this length",
        required=False,
    )
    must_have_name = OptBool(
        True,
        "Require the username to appear in the profile page body",
        required=False,
    )
    scan_permutations = OptBool(
        False,
        "Also test common typo and separator variations",
        required=False,
    )
    max_sites = OptString("25", "Maximum catalog sites to scan per username", required=False)
    concurrency = OptString("10", "Maximum concurrent site checks", required=False)
    timeout = OptString("6", "HTTP timeout in seconds per site check", required=False)
    output_file = OptString("", "Optional JSON output file", required=False)

    def _to_int(self, value, default_value: int, *, min_value: int = 1, max_value: int | None = None) -> int:
        try:
            parsed = int(str(value).strip())
        except Exception:
            parsed = default_value
        parsed = max(min_value, parsed)
        if max_value is not None:
            parsed = min(max_value, parsed)
        return parsed

    def run(self):
        username = str(self.username).strip()
        if not username:
            print_warning("No username provided; skipping search")
            return {
                "username": "",
                "skipped": True,
                "reason": "empty_username",
                "count": 0,
                "findings": [],
            }

        min_len = self._to_int(self.min_username_length, 4, min_value=1, max_value=64)
        max_sites = self._to_int(self.max_sites, 25, min_value=1, max_value=200)
        concurrency = self._to_int(self.concurrency, 10, min_value=1, max_value=50)
        timeout_seconds = float(self._to_int(self.timeout, 6, min_value=1, max_value=30))

        print_info(f"Username search: {username}")
        data = search_username_accounts_sync(
            username,
            min_username_length=min_len,
            must_have_name=bool(self.must_have_name),
            scan_permutations=bool(self.scan_permutations),
            max_sites=max_sites,
            concurrency=concurrency,
            timeout_seconds=timeout_seconds,
        )

        for message in data.get("messages", []):
            if data.get("skipped"):
                print_warning(message)
            elif "Found " in message:
                print_success(message)
            else:
                print_info(message)

        findings = data.get("findings", [])
        if findings:
            print_success(f"Found {len(findings)} account(s)")
            for item in findings[:20]:
                match_kind = item.get("account_match", "exact")
                print_info(
                    f"  [{item.get('platform')}] {item.get('profile_url')} "
                    f"(user={item.get('username')}, match={match_kind})"
                )
            if len(findings) > 20:
                print_info(f"  ... and {len(findings) - 20} more")
        elif not data.get("skipped"):
            print_warning("No matching accounts found in the scanned site set")

        if self.output_file:
            try:
                parent = os.path.dirname(str(self.output_file))
                if parent:
                    os.makedirs(parent, exist_ok=True)
                with open(str(self.output_file), "w") as fp:
                    json.dump(data, fp, indent=2)
                print_success(f"Results saved to {self.output_file}")
            except Exception as exc:
                print_error(f"Failed to save output: {exc}")

        return data

    def get_graph_nodes(self, data):
        if not isinstance(data, dict) or data.get("skipped"):
            return [], []

        username = data.get("username", "username")
        nodes = []
        edges = []

        for idx, item in enumerate(data.get("findings", [])[:30]):
            nid = f"social_{idx}"
            label = f"@{item.get('username')} on {item.get('platform')}"
            nodes.append({
                "id": nid,
                "label": label,
                "group": "hostname",
                "icon": "👤",
            })
            edge_label = "has account" if item.get("account_match") == "exact" else "similar account"
            edges.append({
                "from": username,
                "to": nid,
                "label": edge_label,
            })

        return nodes, edges
