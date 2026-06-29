#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json

from kittysploit import *
from lib.post.gcp import GcpPostMixin


class Module(Post, GcpPostMixin):
    __info__ = {
        "name": "GCP Whoami",
        "description": "Display the identity and scopes of the current GCP API session",
        "author": "KittySploit Team",
        "session_type": SessionType.GCP_API,
        "tags": ["gcp", "cloud", "enumeration", "identity"],
        "agent": {
            "risk": "passive",
            "effects": ["api_request"],
            "expected_requests": 1,
            "reversible": True,
            "approval_required": False,
            "produces": ["risk_signals"],
        },
    }

    export_json = OptString("", "Optional output JSON file", False)

    def run(self):
        try:
            print_info("Resolving GCP session identity...")
            whoami = self._gcp_whoami()
            if not whoami:
                print_error("Could not resolve session identity")
                return False

            project_id = whoami.get("project_id", "")
            client_email = whoami.get("client_email", "")
            scopes = whoami.get("scopes") or []

            print_info("=" * 80)
            print_success("GCP session identity")
            print_info(f"  project_id:   {project_id or 'unknown'}")
            print_info(f"  client_email: {client_email or 'unknown'}")
            print_info(f"  member:       {self._gcp_member() or 'unknown'}")
            print_info(f"  scopes ({len(scopes)}):")
            for scope in scopes:
                print_info(f"    - {scope}")

            exported = self._gcp_export_json(str(self.export_json or ""), whoami)
            if exported:
                print_success(f"Identity exported to {exported}")

            return self.module_result(success=True, data=whoami)
        except Exception as exc:
            print_error(f"Whoami gather failed: {exc}")
            return False
