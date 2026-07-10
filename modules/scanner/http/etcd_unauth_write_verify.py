#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Verify unauthenticated etcd key-value writes (reversible probe)."""

import base64
import json
import secrets

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.scanner.http.response_validation import parse_json_response


class Module(Scanner, Http_client):
    __info__ = {
        "name": "etcd Unauthenticated Write Verification",
        "description": "Tests reversible etcd v3 KV put/delete when write probe is enabled.",
        "author": ["KittySploit Team"],
        "severity": "critical",
        "tags": ["etcd", "kubernetes", "scanner", "unauth", "verify", "misconfig"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 4,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals"],
            "chain": {"produces_capabilities": ["k8s_misconfig", "unauth_write"]},
        },
    }

    write_probe = OptBool(False, "Perform reversible PUT/DELETE key test (requires approval)", required=False)

    def run(self):
        r = self.http_request(method="GET", path="/v3/maintenance/status", allow_redirects=False)
        data, err = parse_json_response(r) if r else (None, "bad_status")
        if err or not data:
            r = self.http_request(method="GET", path="/version", allow_redirects=False)
            if not r or r.status_code != 200 or "etcd" not in (r.text or "").lower():
                return False
            if not self.write_probe:
                self.set_info(severity="medium", reason="etcd API reachable; enable write_probe to confirm writes")
                return True

        if not self.write_probe:
            self.set_info(severity="high", reason="etcd maintenance API exposed without authentication", confidence="medium")
            return True

        key = f"/kittysploit-probe-{secrets.token_hex(4)}"
        value = secrets.token_hex(6)
        payload = {
            "key": base64.b64encode(key.encode("utf-8")).decode("ascii"),
            "value": base64.b64encode(value.encode("utf-8")).decode("ascii"),
        }
        put = self.http_request(
            method="POST",
            path="/v3/kv/put",
            data=json.dumps(payload),
            headers={"Content-Type": "application/json"},
            allow_redirects=False,
        )
        if not put or put.status_code not in (200, 201):
            return False

        delete_payload = {"key": base64.b64encode(key.encode("utf-8")).decode("ascii")}
        delete = self.http_request(
            method="POST",
            path="/v3/kv/deleterange",
            data=json.dumps(delete_payload),
            headers={"Content-Type": "application/json"},
            allow_redirects=False,
        )
        self.set_info(
            severity="critical",
            reason="etcd accepted unauthenticated KV put/delete probe",
            key=key,
            confidence="high",
            cleaned=bool(delete and delete.status_code in (200, 201)),
        )
        return True
