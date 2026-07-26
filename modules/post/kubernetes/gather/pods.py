#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Kubernetes Pods gather — list pods and summarize privileged / hostPath risks."""

from kittysploit import *
from lib.protocols.kubernetes.kubernetes_session_mixin import KubernetesSessionMixin
import json


class Module(Post, KubernetesSessionMixin):
    __info__ = {
        "name": "Kubernetes List Pods",
        "description": "Lists pods in a namespace (or all namespaces) and flags privileged / hostPath containers",
        "author": "KittySploit Team",
        "version": "1.0.0",
        "session_type": SessionType.KUBERNETES,
        "tags": ["kubernetes", "k8s", "cloud", "gather", "pods"],
        "agent": {
            "risk": "passive",
            "effects": ["api_request"],
            "expected_requests": 2,
            "reversible": True,
            "approval_required": False,
            "produces": ["ot_assets", "tech_hints"],
            "chain": {
                "consumes_capabilities": ["cloud_identity"],
                "produces_capabilities": [{"capability": "k8s_pods", "from_detail": ""}],
                "suggested_followups": [
                    "post/kubernetes/manage/exec_pod",
                    "post/kubernetes/gather/secrets",
                ],
            },
        },
    }

    namespace = OptString("", "Namespace (empty = session default)", False)
    all_namespaces = OptBool(False, "List pods across all namespaces (-A)", False)
    label_selector = OptString("", "Label selector filter", False)
    show_risky = OptBool(True, "Highlight privileged / hostNetwork / hostPath pods", False)
    export_json = OptString("", "Optional output JSON file", False)
    store_results = OptBool(True, "Store results in session.data['pods']", False)

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
        selector = str(self.label_selector or "").strip()

        print_status("Listing pods..." + (" (all namespaces)" if all_ns else f" (ns={ns})"))
        result = client.list_pods(namespace=ns, all_namespaces=all_ns, label_selector=selector)
        if not result.ok:
            print_error(result.error or f"HTTP {result.status_code}")
            return False

        items = (result.body or {}).get("items") or []
        rows = []
        risky = []
        for item in items:
            meta = item.get("metadata") or {}
            spec = item.get("spec") or {}
            status = item.get("status") or {}
            row = {
                "name": meta.get("name", ""),
                "namespace": meta.get("namespace", ns),
                "phase": status.get("phase", ""),
                "node": spec.get("nodeName", ""),
                "service_account": spec.get("serviceAccountName") or spec.get("serviceAccount") or "default",
                "host_network": bool(spec.get("hostNetwork")),
                "host_pid": bool(spec.get("hostPID")),
                "host_ipc": bool(spec.get("hostIPC")),
                "privileged": False,
                "host_path": False,
                "containers": [],
            }
            for container in (spec.get("containers") or []) + (spec.get("initContainers") or []):
                sc = (container.get("securityContext") or {})
                priv = bool(sc.get("privileged"))
                row["containers"].append(container.get("name", ""))
                if priv:
                    row["privileged"] = True
            for vol in spec.get("volumes") or []:
                if vol.get("hostPath"):
                    row["host_path"] = True
                    break
            rows.append(row)
            if row["privileged"] or row["host_network"] or row["host_pid"] or row["host_path"]:
                risky.append(row)

        print_info("=" * 80)
        print_success(f"Found {len(rows)} pod(s)")
        for row in rows[:50]:
            flags = []
            if row["privileged"]:
                flags.append("privileged")
            if row["host_network"]:
                flags.append("hostNetwork")
            if row["host_path"]:
                flags.append("hostPath")
            flag_s = f" [{','.join(flags)}]" if flags else ""
            print_info(
                f"  {row['namespace']}/{row['name']}  "
                f"phase={row['phase']}  sa={row['service_account']}{flag_s}"
            )
        if len(rows) > 50:
            print_info(f"  ... {len(rows) - 50} more")

        if bool(self.show_risky) and risky:
            print_warning(f"Risky pods: {len(risky)}")
            for row in risky[:20]:
                print_warning(f"  {row['namespace']}/{row['name']}")

        report = {
            "namespace": None if all_ns else ns,
            "all_namespaces": all_ns,
            "count": len(rows),
            "risky_count": len(risky),
            "pods": rows,
        }

        if bool(self.store_results):
            session = self._resolve_session()
            if session:
                data = session.data if isinstance(session.data, dict) else {}
                data["pods"] = report
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
