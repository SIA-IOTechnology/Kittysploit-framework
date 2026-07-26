#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Kubernetes RBAC privilege-escalation path analysis."""

from kittysploit import *
from lib.protocols.kubernetes.kubernetes_session_mixin import KubernetesSessionMixin
import json


# Practical RBAC privilege escalation / high-impact permission patterns
PRIVESC_CHECKS = [
    {
        "id": "escalate_clusterrole",
        "name": "ClusterRole escalate / bind",
        "severity": "CRITICAL",
        "impact": "Can grant yourself cluster-admin via escalate/bind on clusterroles.",
        "checks": [
            ("escalate", "clusterroles", "rbac.authorization.k8s.io"),
            ("bind", "clusterroles", "rbac.authorization.k8s.io"),
            ("create", "clusterrolebindings", "rbac.authorization.k8s.io"),
        ],
    },
    {
        "id": "impersonate",
        "name": "User / SA impersonation",
        "severity": "CRITICAL",
        "impact": "Can impersonate privileged users or service accounts.",
        "checks": [
            ("impersonate", "users", "authentication.k8s.io"),
            ("impersonate", "groups", "authentication.k8s.io"),
            ("impersonate", "serviceaccounts", ""),
        ],
    },
    {
        "id": "secrets_get",
        "name": "Secret read access",
        "severity": "HIGH",
        "impact": "Can read service account tokens and application credentials from Secrets.",
        "checks": [
            ("get", "secrets", ""),
            ("list", "secrets", ""),
        ],
    },
    {
        "id": "pod_exec",
        "name": "Pod exec / attach",
        "severity": "HIGH",
        "impact": "Can execute commands inside running pods and pivot to workloads.",
        "checks": [
            ("create", "pods/exec", ""),
            ("get", "pods/exec", ""),
            ("create", "pods/attach", ""),
        ],
    },
    {
        "id": "pod_create_privileged",
        "name": "Create pods (privileged pivot)",
        "severity": "HIGH",
        "impact": "Can create privileged pods or pods mounting hostPath / node SA tokens.",
        "checks": [
            ("create", "pods", ""),
            ("create", "deployments", "apps"),
            ("create", "daemonsets", "apps"),
            ("create", "jobs", "batch"),
            ("create", "cronjobs", "batch"),
        ],
    },
    {
        "id": "nodes_proxy",
        "name": "Nodes proxy / kubelet",
        "severity": "HIGH",
        "impact": "Can reach kubelet APIs via nodes/proxy and often run arbitrary pods on nodes.",
        "checks": [
            ("get", "nodes", ""),
            ("create", "nodes/proxy", ""),
            ("get", "nodes/proxy", ""),
        ],
    },
    {
        "id": "portforward",
        "name": "Pod port-forward",
        "severity": "MEDIUM",
        "impact": "Can tunnel to internal services exposed only inside the cluster network.",
        "checks": [
            ("create", "pods/portforward", ""),
            ("get", "pods/portforward", ""),
        ],
    },
    {
        "id": "tokenrequest",
        "name": "TokenRequest on service accounts",
        "severity": "HIGH",
        "impact": "Can mint tokens for other service accounts.",
        "checks": [
            ("create", "serviceaccounts/token", ""),
        ],
    },
]


class Module(Post, KubernetesSessionMixin):
    __info__ = {
        "name": "Kubernetes RBAC PrivEsc",
        "description": (
            "Analyzes SelfSubjectRulesReview / SelfSubjectAccessReview results for "
            "practical Kubernetes RBAC privilege-escalation paths"
        ),
        "author": "KittySploit Team",
        "version": "1.0.0",
        "session_type": SessionType.KUBERNETES,
        "tags": ["kubernetes", "k8s", "rbac", "privilege-escalation", "analyze"],
        "references": [
            "https://kubernetes.io/docs/reference/access-authn-authz/rbac/",
            "https://attack.mitre.org/techniques/T1078/",
        ],
        "agent": {
            "risk": "intrusive",
            "effects": ["api_request"],
            "expected_requests": 20,
            "reversible": True,
            "approval_required": True,
            "produces": ["risk_signals"],
            "chain": {
                "consumes_capabilities": ["cloud_identity"],
                "produces_capabilities": [{"capability": "k8s_privesc_paths", "from_detail": ""}],
                "suggested_followups": [
                    "post/kubernetes/gather/secrets",
                    "post/kubernetes/manage/exec_pod",
                ],
            },
        },
    }

    namespace = OptString("", "Namespace for namespaced checks (empty = session default)", False)
    use_access_review = OptBool(
        True,
        "Confirm candidates with SelfSubjectAccessReview (noisier, more accurate)",
        False,
    )
    include_bindings = OptBool(False, "Also list RoleBindings / ClusterRoleBindings (extra API calls)", False)
    export_json = OptString("", "Optional output JSON file", False)
    store_results = OptBool(True, "Store findings in session.data['rbac_privesc']", False)

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
        print_status(f"Analyzing RBAC privileges (namespace={ns})...")

        rules_status = client.self_subject_rules(ns)
        resource_rules = rules_status.get("resourceRules") or []
        if rules_status.get("error"):
            print_warning(f"SelfSubjectRulesReview issue: {rules_status.get('error')}")

        whoami = client.whoami()
        paths = []
        for check in PRIVESC_CHECKS:
            matched = []
            for verb, resource, group in check["checks"]:
                if self._rule_allows(resource_rules, verb, resource, group):
                    matched.append({"verb": verb, "resource": resource, "group": group, "source": "rules"})
                elif bool(self.use_access_review) and client.can_i(verb, resource, namespace=ns, group=group):
                    matched.append({"verb": verb, "resource": resource, "group": group, "source": "access_review"})
            if matched:
                paths.append(
                    {
                        "id": check["id"],
                        "name": check["name"],
                        "severity": check["severity"],
                        "impact": check["impact"],
                        "matched": matched,
                    }
                )

        bindings = {}
        if bool(self.include_bindings):
            print_status("Listing role bindings...")
            rb = client.list_role_bindings(ns)
            crb = client.list_cluster_role_bindings()
            bindings = {
                "rolebindings": (rb.body or {}).get("items") if rb.ok else [],
                "clusterrolebindings": (crb.body or {}).get("items") if crb.ok else [],
            }

        print_info("=" * 80)
        print_success("Kubernetes RBAC PrivEsc Analysis")
        print_info(f"  username  : {whoami.get('username') or 'unknown'}")
        print_info(f"  namespace : {ns}")
        print_info(f"  rules     : {len(resource_rules)} resource rule(s)")
        print_info(f"  incomplete: {bool(rules_status.get('incomplete'))}")
        print_info("=" * 80)

        if not paths:
            print_success("No high-impact RBAC privilege-escalation paths matched")
        else:
            order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
            for idx, path in enumerate(sorted(paths, key=lambda p: order.get(p["severity"], 99)), 1):
                print_warning(f"[{idx}] {path['name']} ({path['severity']})")
                print_info(f"  Impact: {path['impact']}")
                for m in path["matched"]:
                    g = m["group"] or "core"
                    print_info(f"  Allowed: {m['verb']} {g}/{m['resource']} ({m['source']})")
                print_info("-" * 80)

        report = {
            "username": whoami.get("username"),
            "namespace": ns,
            "rules_count": len(resource_rules),
            "incomplete": bool(rules_status.get("incomplete")),
            "paths": paths,
            "bindings_included": bool(self.include_bindings),
            "bindings_summary": {
                "rolebindings": len(bindings.get("rolebindings") or []),
                "clusterrolebindings": len(bindings.get("clusterrolebindings") or []),
            }
            if bindings
            else {},
        }

        if bool(self.store_results):
            session = self._resolve_session()
            if session:
                data = session.data if isinstance(session.data, dict) else {}
                data["rbac_privesc"] = report
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

    def _rule_allows(self, rules, verb: str, resource: str, group: str) -> bool:
        verb = verb.lower()
        resource = resource.lower()
        group = (group or "").lower()
        for rule in rules:
            verbs = [v.lower() for v in (rule.get("verbs") or [])]
            if "*" not in verbs and verb not in verbs:
                continue
            api_groups = [g.lower() for g in (rule.get("apiGroups") or [])]
            # empty group means core; rules use "" for core
            if group:
                if "*" not in api_groups and group not in api_groups:
                    continue
            else:
                if api_groups and "*" not in api_groups and "" not in api_groups and "core" not in api_groups:
                    # still allow if resource matches broadly
                    pass
            resources = [r.lower() for r in (rule.get("resources") or [])]
            if "*" in resources or resource in resources:
                return True
            # pods/exec style subresource may appear as pods/exec
            if "/" in resource:
                parent = resource.split("/", 1)[0]
                if parent in resources and (f"{parent}/*" in resources or resource in resources):
                    return True
        return False
