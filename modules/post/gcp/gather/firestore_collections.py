#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json

from kittysploit import *
from lib.post.gcp import GcpPostMixin


class Module(Post, GcpPostMixin):
    __info__ = {
        "name": "GCP Firestore Collections",
        "description": "List top-level Firestore collection IDs in the current GCP project",
        "author": "KittySploit Team",
        "session_type": SessionType.GCP_API,
        "tags": ["gcp", "firestore", "firebase", "enumeration"],
        "agent": {
            "risk": "passive",
            "effects": ["api_request"],
            "expected_requests": 1,
            "reversible": True,
            "approval_required": False,
            "produces": ["risk_signals"],
        },
    }

    name_filter = OptString("", "Filter collections by collectionId substring", False)
    export_json = OptString("", "Optional output JSON file", False)

    def run(self):
        try:
            project_id = self._gcp_project_id()
            if not project_id:
                print_error("Could not resolve project_id from session")
                return False

            print_info(f"Listing Firestore collections in {project_id}...")
            result = self._gcp_request("firestore_collections")
            if not result.get("ok"):
                print_error(f"Firestore API request failed: {result.get('raw', '')[:500]}")
                return False

            collections = (result.get("body") or {}).get("collectionIds") or []
            name_filter = str(self.name_filter or "").strip().lower()
            if name_filter:
                collections = [cid for cid in collections if name_filter in str(cid).lower()]

            print_info("=" * 80)
            if not collections:
                print_warning("No Firestore collections found")
            else:
                for collection_id in collections:
                    print_info(f"  {collection_id}")
                print_success(f"Found {len(collections)} collection(s)")

            if self.export_json:
                exported = self._gcp_export_json(str(self.export_json or ""), {"project_id": project_id, "collectionIds": collections})
                if exported:
                    print_success(f"Results exported to {exported}")

            return self.module_result(
                success=True,
                data={"project_id": project_id, "collectionIds": collections},
            )
        except Exception as exc:
            print_error(f"Firestore collection enumeration failed: {exc}")
            return False
