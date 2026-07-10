#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Generate likely usernames from a person's name and aliases."""

from __future__ import annotations

import json
import os

from kittysploit import *

from lib.osint.person_usernames import generate_person_usernames


class Module(Auxiliary):
    __info__ = {
        "name": "Person to Usernames",
        "author": ["KittySploit Team"],
        "description": (
            "Generate likely username candidates from a person's full name, "
            "structured name fields, display name, and aliases."
        ),
        "tags": ["osint", "identity", "username", "person", "passive"],
        "agent": {
            "risk": "passive",
            "effects": ["analysis"],
            "expected_requests": 0,
            "reversible": True,
            "approval_required": False,
            "produces": ["username_candidates"],
        },
    }

    name = OptString("", "Person full name or entity value", required=True)
    first_name = OptString("", "Optional first name", required=False)
    last_name = OptString("", "Optional last name", required=False)
    display_name = OptString("", "Optional display name", required=False)
    aliases = OptString("", "Optional aliases (comma-separated)", required=False)
    max_results = OptString("10", "Maximum username candidates to return", required=False)
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
        person_name = str(self.name).strip()
        if not person_name and not str(self.first_name).strip() and not str(self.display_name).strip():
            print_warning("No person name provided; skipping username generation")
            return {
                "person": "",
                "skipped": True,
                "reason": "empty_name",
                "count": 0,
                "candidates": [],
            }

        max_results = self._to_int(self.max_results, 10, min_value=1, max_value=50)
        print_info(f"Generating username candidates for: {person_name or self.display_name or self.first_name}")

        data = generate_person_usernames(
            name=person_name,
            first_name=str(self.first_name).strip(),
            last_name=str(self.last_name).strip(),
            display_name=str(self.display_name).strip(),
            aliases=str(self.aliases).strip(),
            max_results=max_results,
        )

        for message in data.get("messages", []):
            if data.get("skipped"):
                print_warning(message)
            else:
                print_success(message)

        candidates = data.get("candidates", [])
        if candidates:
            for item in candidates:
                print_info(
                    f"  @{item.get('username')} "
                    f"(confidence={item.get('confidence')}, {item.get('rationale')})"
                )

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

        person = data.get("person", "person")
        nodes = []
        edges = []

        for idx, item in enumerate(data.get("candidates", [])[:20]):
            nid = f"username_{idx}"
            label = f"@{item.get('username')} ({item.get('confidence', 0)})"
            nodes.append({
                "id": nid,
                "label": label,
                "group": "hostname",
                "icon": "👤",
            })
            edges.append({
                "from": person,
                "to": nid,
                "label": "possible username",
            })

        return nodes, edges
