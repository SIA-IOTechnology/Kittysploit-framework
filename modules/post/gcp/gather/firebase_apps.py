#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json

from kittysploit import *
from lib.post.gcp import GcpPostMixin


class Module(Post, GcpPostMixin):
    __info__ = {
        "name": "GCP Firebase Apps",
        "description": "Enumerate Firebase web apps in the current GCP project",
        "author": "KittySploit Team",
        "session_type": SessionType.GCP_API,
        "tags": ["gcp", "firebase", "enumeration"],
        "agent": {
            "risk": "passive",
            "effects": ["api_request"],
            "expected_requests": 1,
            "reversible": True,
            "approval_required": False,
            "produces": ["risk_signals"],
        },
    }

    name_filter = OptString("", "Filter apps by display name or appId substring", False)
    export_json = OptString("", "Optional output JSON file", False)

    def run(self):
        try:
            project_id = self._gcp_project_id()
            if not project_id:
                print_error("Could not resolve project_id from session")
                return False

            print_info(f"Enumerating Firebase web apps in {project_id}...")
            result = self._gcp_request("firebase_apps")
            if not result.get("ok"):
                print_error(f"Firebase API request failed: {result.get('raw', '')[:500]}")
                return False

            apps = (result.get("body") or {}).get("apps") or []
            name_filter = str(self.name_filter or "").strip().lower()
            rows = []
            for item in apps:
                app_id = str(item.get("appId") or "")
                display_name = str(item.get("displayName") or "")
                if name_filter and name_filter not in app_id.lower() and name_filter not in display_name.lower():
                    continue
                rows.append(
                    {
                        "appId": app_id,
                        "displayName": display_name,
                        "name": item.get("name"),
                        "projectId": item.get("projectId"),
                        "webId": item.get("webId"),
                        "apiKeyId": item.get("apiKeyId"),
                    }
                )

            print_info("=" * 80)
            if not rows:
                print_warning("No Firebase web apps found")
            else:
                for row in rows:
                    label = row.get("displayName") or row.get("appId")
                    print_info(f"{label} appId={row.get('appId')}")
                    if row.get("apiKeyId"):
                        print_info(f"  apiKeyId: {row['apiKeyId']}")
                print_success(f"Found {len(rows)} app(s)")

            if self.export_json:
                exported = self._gcp_export_json(str(self.export_json or ""), {"project_id": project_id, "apps": rows})
                if exported:
                    print_success(f"Results exported to {exported}")

            return self.module_result(success=True, data={"project_id": project_id, "apps": rows})
        except Exception as exc:
            print_error(f"Firebase apps enumeration failed: {exc}")
            return False
