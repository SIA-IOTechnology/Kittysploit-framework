#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Kubernetes Whoami — identity and effective rules for the current API session."""

from kittysploit import *
from lib.protocols.kubernetes.kubernetes_session_mixin import KubernetesSessionMixin
import json


class Module(Post, KubernetesSessionMixin):
    __info__ = {
        "name": "Kubernetes Whoami",
        "description": "Resolves the current Kubernetes identity via SelfSubjectReview and SelfSubjectRulesReview",
        "author": "KittySploit Team",
        "version": "1.0.0",
        "session_type": SessionType.KUBERNETES,
        "tags": ["kubernetes", "k8s", "cloud", "gather", "identity"],
        "agent": {
            "risk": "passive",
            "effects": ["api_request"],
            "expected_requests": 2,
            "reversible": True,
            "approval_required": False,
            "produces": ["cloud_identity"],
            "chain": {
                "produces_capabilities": [{"capability": "cloud_identity", "from_detail": ""}],
                "suggested_followups": [
                    "post/kubernetes/gather/pods",
                    "post/kubernetes/analyze/rbac_privesc",
                ],
            },
        },
    }

    export_json = OptString("", "Optional output JSON file", False)
    store_results = OptBool(True, "Store identity in session.data['whoami']", False)

    def check(self):
        sid = str(self.session_id or "").strip()
        if not sid:
            print_error("Session ID not set")
            return False
        session = self.framework.session_manager.get_session(sid) if self.framework else None
        if not session:
            print_error("Session not found")
            return False
        if str(session.session_type).lower() != SessionType.KUBERNETES.value:
            print_error(f"Session is not Kubernetes (type: {session.session_type})")
            return False
        try:
            self.open_kubernetes()
            return True
        except Exception as exc:
            print_error(str(exc))
            return False

    def run(self):
        client = self.open_kubernetes()
        print_status("Resolving Kubernetes session identity...")
        whoami = client.whoami()

        print_info("=" * 80)
        print_success("Kubernetes session identity")
        print_info(f"  api_server : {whoami.get('api_server')}")
        print_info(f"  namespace  : {whoami.get('namespace')}")
        print_info(f"  username   : {whoami.get('username') or 'unknown'}")
        print_info(f"  uid        : {whoami.get('uid') or 'n/a'}")
        groups = whoami.get("groups") or []
        if groups:
            print_info(f"  groups ({len(groups)}):")
            for group in groups[:20]:
                print_info(f"    - {group}")
        version = whoami.get("version") or {}
        if version:
            print_info(f"  version    : {version.get('gitVersion') or 'unknown'}")

        rules = whoami.get("rules") or []
        print_info(f"  resource rules in ns '{whoami.get('rules_namespace')}': {len(rules)}")
        for rule in rules[:15]:
            verbs = ",".join(rule.get("verbs") or [])
            resources = ",".join(rule.get("resources") or [])
            print_info(f"    [{verbs}] {resources}")
        if len(rules) > 15:
            print_info(f"    ... {len(rules) - 15} more")

        if bool(self.store_results):
            session = self._resolve_session()
            if session:
                data = session.data if isinstance(session.data, dict) else {}
                data["whoami"] = whoami
                session.data = data

        out = str(self.export_json or "").strip()
        if out:
            try:
                with open(out, "w", encoding="utf-8") as handle:
                    json.dump(whoami, handle, indent=2)
                print_success(f"Exported to {out}")
            except OSError as exc:
                print_error(f"Export failed: {exc}")

        return True
