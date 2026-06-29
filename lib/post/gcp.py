#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Shared helpers for GCP API post modules."""

from __future__ import annotations

import base64
import fnmatch
import json
import os
import re
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import quote


PRIMITIVE_ROLES = frozenset(
    {
        "roles/owner",
        "roles/editor",
        "roles/viewer",
        "roles/iam.securityAdmin",
        "roles/iam.serviceAccountAdmin",
        "roles/iam.serviceAccountKeyAdmin",
        "roles/iam.serviceAccountTokenCreator",
    }
)

PUBLIC_MEMBERS = frozenset({"allUsers", "allAuthenticatedUsers"})

PRIVESC_PATH_RULES = [
    {
        "id": "set_iam_policy",
        "name": "Project IAM policy takeover",
        "severity": "CRITICAL",
        "required": ["resourcemanager.projects.setIamPolicy"],
        "any_of": [],
        "impact": "Can grant Owner/Editor to the current principal and fully control the project.",
        "validation": ["iam_policy"],
    },
    {
        "id": "sa_impersonation",
        "name": "Service account impersonation",
        "severity": "HIGH",
        "required": [],
        "any_of": [
            "iam.serviceAccounts.actAs",
            "iam.serviceAccounts.getAccessToken",
            "iam.serviceAccounts.implicitDelegation",
            "iam.serviceAccounts.signBlob",
            "iam.serviceAccounts.signJwt",
        ],
        "impact": "Can obtain short-lived credentials for privileged service accounts.",
        "validation": ["service_accounts"],
    },
    {
        "id": "sa_key_create",
        "name": "Service account key minting",
        "severity": "HIGH",
        "required": [],
        "any_of": ["iam.serviceAccountKeys.create", "iam.serviceAccountKeys.createTagBinding"],
        "impact": "Can create long-lived JSON keys for service accounts and exfiltrate them.",
        "validation": ["service_accounts"],
    },
    {
        "id": "sa_set_iam",
        "name": "Service account IAM takeover",
        "severity": "HIGH",
        "required": [],
        "any_of": ["iam.serviceAccounts.setIamPolicy", "iam.serviceAccounts.update"],
        "impact": "Can grant yourself Token Creator on privileged service accounts.",
        "validation": ["service_accounts", "iam_policy"],
    },
    {
        "id": "compute_actas",
        "name": "Compute + actAs chain",
        "severity": "HIGH",
        "required": ["iam.serviceAccounts.actAs"],
        "any_of": [
            "compute.instances.create",
            "compute.instances.setServiceAccount",
            "compute.instances.update",
        ],
        "impact": "Can launch or modify VMs running under a privileged service account.",
        "validation": ["compute_instances"],
    },
    {
        "id": "cloudfunctions_deploy",
        "name": "Cloud Functions deploy + actAs",
        "severity": "HIGH",
        "required": ["iam.serviceAccounts.actAs"],
        "any_of": [
            "cloudfunctions.functions.create",
            "cloudfunctions.functions.update",
            "cloudfunctions.functions.sourceCodeSet",
        ],
        "impact": "Can deploy functions that run code as a privileged service account.",
        "validation": ["functions_v1", "functions_v2"],
    },
    {
        "id": "cloud_run_deploy",
        "name": "Cloud Run deploy + actAs",
        "severity": "HIGH",
        "required": ["iam.serviceAccounts.actAs"],
        "any_of": ["run.services.create", "run.services.update", "run.jobs.create"],
        "impact": "Can deploy Cloud Run workloads under privileged identities.",
        "validation": ["cloud_run_jobs"],
    },
    {
        "id": "secret_access",
        "name": "Secret Manager access chain",
        "severity": "MEDIUM",
        "required": [],
        "any_of": [
            "secretmanager.secrets.get",
            "secretmanager.versions.access",
            "secretmanager.versions.list",
        ],
        "impact": "Can read stored secrets and pivot with recovered credentials.",
        "validation": ["secrets"],
    },
    {
        "id": "storage_admin",
        "name": "Storage data exfiltration",
        "severity": "MEDIUM",
        "required": [],
        "any_of": [
            "storage.objects.get",
            "storage.objects.list",
            "storage.buckets.getIamPolicy",
            "storage.buckets.setIamPolicy",
        ],
        "impact": "Can read or re-share bucket data and IAM for lateral movement.",
        "validation": ["storage_buckets"],
    },
    {
        "id": "deployment_manager",
        "name": "Deployment Manager abuse",
        "severity": "HIGH",
        "required": [],
        "any_of": ["deploymentmanager.deployments.create", "deploymentmanager.deployments.update"],
        "impact": "Can deploy arbitrary GCP resources via deployment templates.",
        "validation": ["enabled_services"],
    },
]


_HTTP_PREFIX = re.compile(r"^HTTP\s+(\d+)\s+(\S+)\s*\n?", re.MULTILINE)


def parse_gcp_console_output(text: str) -> Tuple[Optional[int], str, Any]:
    """Parse ``HTTP <code> <url>\\n<body>`` returned by the GCP API console."""
    raw = (text or "").strip()
    if not raw:
        return None, "", None

    match = _HTTP_PREFIX.match(raw)
    if not match:
        try:
            return 200, "", json.loads(raw)
        except Exception:
            return None, "", raw

    status = int(match.group(1))
    url = match.group(2)
    body_text = raw[match.end() :].strip()
    if not body_text:
        return status, url, None
    try:
        return status, url, json.loads(body_text)
    except Exception:
        return status, url, body_text


class GcpPostMixin:
    """Mixin providing GCP API console helpers for post modules."""

    def _gcp_execute(self, command: str) -> str:
        return (self.cmd_execute(command) or "").strip()

    def _gcp_request(self, command: str) -> Dict[str, Any]:
        output = self._gcp_execute(command)
        status, url, body = parse_gcp_console_output(output)
        ok = status is not None and 200 <= status < 300
        return {
            "status_code": status,
            "url": url,
            "body": body,
            "ok": ok,
            "raw": output,
        }

    def _gcp_get(self, url: str) -> Dict[str, Any]:
        return self._gcp_request(f"get {url}")

    def _gcp_post(self, url: str, payload: Optional[dict] = None) -> Dict[str, Any]:
        if payload is None:
            return self._gcp_request(f"post {url}")
        return self._gcp_request(f"post {url} {json.dumps(payload, separators=(',', ':'))}")

    def _gcp_whoami(self) -> Dict[str, Any]:
        result = self._gcp_request("whoami")
        body = result.get("body")
        return body if isinstance(body, dict) else {}

    def _gcp_project_id(self) -> str:
        whoami = self._gcp_whoami()
        return str(whoami.get("project_id") or "").strip()

    def _gcp_client_email(self) -> str:
        whoami = self._gcp_whoami()
        return str(whoami.get("client_email") or "").strip()

    def _gcp_member(self) -> str:
        email = self._gcp_client_email()
        return f"serviceAccount:{email}" if email else ""

    @staticmethod
    def _quote_project(project_id: str) -> str:
        return quote(project_id, safe="")

    def _project_test_iam_permissions(self, project_id: str, permissions: List[str]) -> List[str]:
        granted: List[str] = []
        url = (
            f"https://cloudresourcemanager.googleapis.com/v1/projects/"
            f"{self._quote_project(project_id)}:testIamPermissions"
        )
        batch_size = 100
        for offset in range(0, len(permissions), batch_size):
            batch = permissions[offset : offset + batch_size]
            result = self._gcp_post(url, {"permissions": batch})
            body = result.get("body")
            if isinstance(body, dict):
                granted.extend(body.get("permissions") or [])
        return sorted(set(granted))

    @staticmethod
    def _flatten_compute_instances(body: Any) -> List[dict]:
        if not isinstance(body, dict):
            return []
        items = body.get("items")
        instances: List[dict] = []
        if isinstance(items, list):
            return [item for item in items if isinstance(item, dict)]
        if isinstance(items, dict):
            for zone_data in items.values():
                if isinstance(zone_data, dict):
                    for instance in zone_data.get("instances") or []:
                        if isinstance(instance, dict):
                            instances.append(instance)
                elif isinstance(zone_data, list):
                    instances.extend(item for item in zone_data if isinstance(item, dict))
        return instances

    @staticmethod
    def _summarize_bindings(iam_policy: Any) -> Dict[str, Any]:
        if not isinstance(iam_policy, dict):
            return {"binding_count": 0, "roles": [], "members": []}
        bindings = iam_policy.get("bindings") or []
        roles = sorted({str(item.get("role") or "") for item in bindings if item.get("role")})
        members = sorted(
            {
                member
                for item in bindings
                for member in (item.get("members") or [])
                if member
            }
        )
        return {
            "binding_count": len(bindings),
            "roles": roles,
            "members": members,
        }

    def _gcp_body(self, command: str) -> Any:
        result = self._gcp_request(command)
        return result.get("body")

    def _gcp_body_dict(self, command: str) -> Dict[str, Any]:
        body = self._gcp_body(command)
        return body if isinstance(body, dict) else {}

    def _gcp_get_body(self, url: str) -> Any:
        return self._gcp_get(url).get("body")

    def _gcp_iam_bindings(self, policy: Optional[Any] = None) -> List[dict]:
        if policy is None:
            policy = self._gcp_body_dict("iam_policy")
        if isinstance(policy, list):
            return [item for item in policy if isinstance(item, dict)]
        if isinstance(policy, dict):
            return [item for item in (policy.get("bindings") or []) if isinstance(item, dict)]
        return []

    @staticmethod
    def _gcp_to_int(value: Any, default_value: int) -> int:
        try:
            return max(1, int(str(value).strip()))
        except Exception:
            return default_value

    @staticmethod
    def _gcp_as_list(value: Any) -> List[Any]:
        if value is None:
            return []
        if isinstance(value, list):
            return value
        return [value]

    @staticmethod
    def _gcp_is_public_member(member: Any) -> bool:
        member_s = str(member or "").strip()
        if member_s in PUBLIC_MEMBERS:
            return True
        return member_s.endswith(":allUsers") or member_s.endswith(":allAuthenticatedUsers")

    @staticmethod
    def _gcp_is_primitive_role(role: Any) -> bool:
        role_s = str(role or "").strip()
        if role_s in PRIMITIVE_ROLES:
            return True
        return role_s.endswith("/owner") or role_s.endswith("/editor")

    @staticmethod
    def _gcp_permission_matches(permission: str, pattern: str) -> bool:
        return fnmatch.fnmatchcase(str(permission).lower(), str(pattern).lower())

    def _gcp_roles_for_member(self, member_email: str, bindings: Optional[List[dict]] = None) -> List[str]:
        if bindings is None:
            bindings = self._gcp_iam_bindings()
        elif isinstance(bindings, dict):
            bindings = self._gcp_iam_bindings(bindings)
        email = str(member_email or "").strip().lower()
        if not email:
            return []
        roles: List[str] = []
        for binding in bindings:
            if not isinstance(binding, dict):
                continue
            role = binding.get("role", "")
            for member in binding.get("members") or []:
                member_l = str(member).lower()
                if email in member_l or member_l.endswith(f":{email}"):
                    roles.append(role)
        return sorted(set(roles))

    def _gcp_fetch_role_permissions(self, role_name: str) -> Set[str]:
        role_name = str(role_name or "").strip()
        if not role_name:
            return set()
        if role_name.startswith(("projects/", "roles/")):
            url = f"https://iam.googleapis.com/v1/{role_name}"
        else:
            url = f"https://iam.googleapis.com/v1/roles/{role_name.lstrip('/')}"
        data = self._gcp_get_body(url)
        if not isinstance(data, dict):
            return set()
        return {str(p) for p in (data.get("includedPermissions") or [])}

    def _gcp_collect_effective_permissions(
        self, member_email: str, bindings: Optional[List[dict]] = None
    ) -> Dict[str, Any]:
        roles = self._gcp_roles_for_member(member_email, bindings=bindings)
        permissions: Set[str] = set()
        role_map: Dict[str, List[str]] = {}
        for role in roles:
            if role in ("roles/owner", "roles/editor"):
                permissions.add("*")
                role_map[role] = ["*"]
                continue
            role_perms = self._gcp_fetch_role_permissions(role)
            permissions |= role_perms
            role_map[role] = sorted(role_perms)
        return {"roles": roles, "permissions": permissions, "role_permissions": role_map}

    def _gcp_has_permission(self, effective_permissions: Set[str], pattern: str) -> bool:
        if "*" in effective_permissions:
            return True
        for perm in effective_permissions:
            if self._gcp_permission_matches(perm, pattern):
                return True
        return False

    def _gcp_matching_permissions(self, effective_permissions: Set[str], patterns: List[str]) -> List[str]:
        matched: List[str] = []
        for pattern in patterns:
            for perm in effective_permissions:
                if perm == "*" or self._gcp_permission_matches(perm, pattern):
                    matched.append(perm if perm != "*" else pattern)
        return sorted(set(matched))

    def _gcp_identify_privesc_paths(self, effective_permissions: Set[str], principal: str) -> List[dict]:
        paths: List[dict] = []
        for rule in PRIVESC_PATH_RULES:
            if any(not self._gcp_has_permission(effective_permissions, req) for req in rule["required"]):
                continue
            if rule["any_of"] and not any(
                self._gcp_has_permission(effective_permissions, perm) for perm in rule["any_of"]
            ):
                continue
            matched: List[str] = []
            matched.extend(self._gcp_matching_permissions(effective_permissions, rule["required"]))
            matched.extend(self._gcp_matching_permissions(effective_permissions, rule["any_of"]))
            paths.append(
                {
                    "id": rule["id"],
                    "name": rule["name"],
                    "severity": rule["severity"],
                    "principal": principal,
                    "matched_permissions": matched,
                    "impact": rule["impact"],
                    "validation_commands": rule["validation"],
                }
            )
        return paths

    def _gcp_public_bindings(self, bindings: Optional[List[dict]] = None) -> List[dict]:
        findings: List[dict] = []
        binding_list = bindings if bindings is not None else self._gcp_iam_bindings()
        for binding in binding_list:
            if not isinstance(binding, dict):
                continue
            role = binding.get("role", "")
            public_members = [
                member for member in binding.get("members") or [] if self._gcp_is_public_member(member)
            ]
            if public_members:
                findings.append({"role": role, "members": public_members})
        return findings

    @staticmethod
    def _gcp_firewall_is_public_source(source_ranges: Any) -> bool:
        for src in GcpPostMixin._gcp_as_list(source_ranges):
            if str(src).strip() in ("0.0.0.0/0", "::/0", "0.0.0.0"):
                return True
        return False

    @staticmethod
    def _gcp_sensitive_ports(ports: Any) -> List[str]:
        sensitive = {
            "22", "23", "3389", "3306", "5432", "6379", "9200", "27017",
            "8080", "8443", "445", "139", "111", "2049",
        }
        matched: List[str] = []
        for item in GcpPostMixin._gcp_as_list(ports):
            item_s = str(item)
            if item_s == "all":
                return ["all"]
            if item_s.split("-", 1)[0] in sensitive:
                matched.append(item_s)
        return matched

    @staticmethod
    def _gcp_instance_external_ip(instance: dict) -> str:
        for iface in GcpPostMixin._gcp_as_list((instance or {}).get("networkInterfaces")):
            for access in GcpPostMixin._gcp_as_list(iface.get("accessConfigs")):
                ip = access.get("natIP") or access.get("natIp")
                if ip:
                    return str(ip)
        return ""

    @staticmethod
    def _gcp_instance_service_account(instance: dict) -> str:
        if not isinstance(instance, dict):
            return ""
        sa = GcpPostMixin._gcp_as_list((instance or {}).get("serviceAccounts"))
        if sa and isinstance(sa[0], dict):
            return str(sa[0].get("email") or "")
        return str((instance or {}).get("serviceAccountEmail") or "")

    @staticmethod
    def _gcp_instance_full_scope(instance: dict) -> bool:
        sa = (instance or {}).get("serviceAccounts") or []
        if not sa:
            return False
        scopes = GcpPostMixin._gcp_as_list(sa[0].get("scopes"))
        return any("auth/cloud-platform" in str(scope) for scope in scopes)

    @staticmethod
    def _gcp_bucket_name(bucket: dict) -> str:
        return str((bucket or {}).get("name") or (bucket or {}).get("id") or "")

    @staticmethod
    def _gcp_output_relpath(path: str) -> str:
        raw = str(path or "").strip()
        if not raw or os.path.isabs(raw):
            return ""
        normalized = raw.replace("\\", "/").lstrip("/")
        if normalized.startswith("output/"):
            normalized = normalized[len("output/") :]
        return normalized

    def _gcp_export_json(self, path: str, payload: Any, *, default_name: str = "") -> str:
        relpath = self._gcp_output_relpath(path) or self._gcp_output_relpath(default_name)
        if not relpath:
            return ""
        content = json.dumps(payload, indent=2, ensure_ascii=False)
        if not self.write_out_dir(relpath, content, quiet=True):
            return ""
        return self.output_dir_path(relpath)

    def _gcp_export_text(self, path: str, content: str, *, default_name: str = "") -> str:
        relpath = self._gcp_output_relpath(path) or self._gcp_output_relpath(default_name)
        if not relpath:
            return ""
        if not self.write_out_dir(relpath, str(content or ""), quiet=True):
            return ""
        return self.output_dir_path(relpath)

    @staticmethod
    def _gcp_mask_value(value: Any, mask: bool = True) -> str:
        text = value if isinstance(value, str) else json.dumps(value, ensure_ascii=False)
        text = str(text or "")
        if not mask:
            return text
        if len(text) <= 8:
            return "*" * len(text)
        return f"{text[:4]}{'*' * (len(text) - 8)}{text[-4:]}"

    def _gcp_paginate_get(
        self,
        url: str,
        items_key: str,
        *,
        max_items: int = 100,
        params: Optional[dict] = None,
    ) -> List[dict]:
        collected: List[dict] = []
        page_token = ""
        base_params = dict(params or {})
        limit = max(1, int(max_items or 100))

        while len(collected) < limit:
            query = dict(base_params)
            if page_token:
                query["pageToken"] = page_token
            separator = "&" if "?" in url else "?"
            param_parts = [f"{quote(str(k), safe='')}={quote(str(v), safe='')}" for k, v in query.items()]
            page_url = url if not param_parts else f"{url}{separator}{'&'.join(param_parts)}"
            result = self._gcp_get(page_url)
            if not result.get("ok"):
                break
            body = result.get("body")
            if not isinstance(body, dict):
                break
            batch = body.get(items_key) or []
            if isinstance(batch, list):
                collected.extend(item for item in batch if isinstance(item, dict))
            page_token = str(body.get("nextPageToken") or "")
            if not page_token:
                break

        return collected[:limit]

    def _gcp_test_permissions(
        self, permissions: List[str], project_id: Optional[str] = None
    ) -> List[str]:
        pid = project_id or self._gcp_project_id()
        if not pid or not permissions:
            return []
        return self._project_test_iam_permissions(pid, permissions)

    def _gcp_generate_access_token(
        self,
        service_account_email: str,
        *,
        scopes: Optional[List[str]] = None,
        lifetime: str = "3600s",
    ) -> Dict[str, Any]:
        scope_list = [item.strip() for item in (scopes or []) if item.strip()]
        payload = {
            "scope": scope_list or ["https://www.googleapis.com/auth/cloud-platform"],
            "lifetime": str(lifetime or "3600s"),
        }
        encoded = quote(str(service_account_email).strip(), safe="")
        url = (
            "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/"
            f"{encoded}:generateAccessToken"
        )
        result = self._gcp_post(url, payload)
        body = result.get("body")
        if result.get("ok") and isinstance(body, dict) and body.get("accessToken"):
            return {
                "target": service_account_email,
                "success": True,
                "accessToken": body.get("accessToken"),
                "expireTime": body.get("expireTime"),
            }
        error = body if isinstance(body, dict) else (result.get("raw") or "")
        return {"target": service_account_email, "success": False, "error": error}

    def _gcp_access_secret_version(self, version_name: str) -> Dict[str, Any]:
        result = self._gcp_post(
            f"https://secretmanager.googleapis.com/v1/{version_name}:access",
            {},
        )
        if not result.get("ok"):
            return {"success": False, "error": (result.get("raw") or "")[:500]}
        body = result.get("body") or {}
        payload = body.get("payload") or {}
        data = payload.get("data")
        if isinstance(data, str):
            try:
                data = base64.b64decode(data).decode("utf-8", errors="replace")
            except Exception:
                pass
        return {"success": True, "payload": data, "name": body.get("name")}

    @staticmethod
    def _gcp_mask_token(token: str) -> str:
        text = str(token or "")
        if len(text) <= 12:
            return "*" * len(text)
        return f"{text[:6]}...{text[-4:]}"

    @staticmethod
    def _gcp_normalize_member(member: str) -> str:
        member_s = str(member or "").strip()
        if not member_s:
            return ""
        if ":" in member_s:
            return member_s
        if member_s.endswith(".gserviceaccount.com"):
            return f"serviceAccount:{member_s}"
        if "@" in member_s:
            return f"user:{member_s}"
        return member_s

    @staticmethod
    def _gcp_merge_iam_binding(policy: dict, role: str, member: str) -> dict:
        policy = dict(policy or {})
        bindings = [dict(item) for item in (policy.get("bindings") or [])]
        member = GcpPostMixin._gcp_normalize_member(member)
        role = str(role or "").strip()
        for binding in bindings:
            if binding.get("role") == role:
                members = list(binding.get("members") or [])
                if member not in members:
                    members.append(member)
                binding["members"] = members
                policy["bindings"] = bindings
                return policy
        bindings.append({"role": role, "members": [member]})
        policy["bindings"] = bindings
        return policy

    def _gcp_get_project_iam_policy(self, project_id: str) -> Dict[str, Any]:
        url = (
            f"https://cloudresourcemanager.googleapis.com/v1/projects/"
            f"{self._quote_project(project_id)}:getIamPolicy"
        )
        result = self._gcp_post(url, {})
        body = result.get("body")
        if result.get("ok") and isinstance(body, dict):
            return {"ok": True, "policy": body}
        return {"ok": False, "error": result.get("raw") or body}

    def _gcp_set_project_iam_policy(self, project_id: str, policy: dict) -> Dict[str, Any]:
        url = (
            f"https://cloudresourcemanager.googleapis.com/v1/projects/"
            f"{self._quote_project(project_id)}:setIamPolicy"
        )
        result = self._gcp_post(url, {"policy": policy})
        body = result.get("body")
        if result.get("ok") and isinstance(body, dict):
            return {"ok": True, "policy": body}
        return {"ok": False, "error": result.get("raw") or body}

    def _gcp_get_service_account_iam_policy(self, project_id: str, email: str) -> Dict[str, Any]:
        encoded = quote(str(email).strip(), safe="")
        url = (
            f"https://iam.googleapis.com/v1/projects/{self._quote_project(project_id)}"
            f"/serviceAccounts/{encoded}:getIamPolicy"
        )
        result = self._gcp_post(url, {})
        body = result.get("body")
        if result.get("ok") and isinstance(body, dict):
            return {"ok": True, "policy": body}
        return {"ok": False, "error": result.get("raw") or body}

    def _gcp_set_service_account_iam_policy(
        self, project_id: str, email: str, policy: dict
    ) -> Dict[str, Any]:
        encoded = quote(str(email).strip(), safe="")
        url = (
            f"https://iam.googleapis.com/v1/projects/{self._quote_project(project_id)}"
            f"/serviceAccounts/{encoded}:setIamPolicy"
        )
        result = self._gcp_post(url, {"policy": policy})
        body = result.get("body")
        if result.get("ok") and isinstance(body, dict):
            return {"ok": True, "policy": body}
        return {"ok": False, "error": result.get("raw") or body}

    def _gcp_create_service_account_key(
        self,
        project_id: str,
        email: str,
        *,
        key_algorithm: str = "KEY_ALG_RSA_2048",
        private_key_type: str = "TYPE_GOOGLE_CREDENTIALS_FILE",
    ) -> Dict[str, Any]:
        encoded = quote(str(email).strip(), safe="")
        url = (
            f"https://iam.googleapis.com/v1/projects/{self._quote_project(project_id)}"
            f"/serviceAccounts/{encoded}/keys"
        )
        payload = {
            "keyAlgorithm": str(key_algorithm or "KEY_ALG_RSA_2048"),
            "privateKeyType": str(private_key_type or "TYPE_GOOGLE_CREDENTIALS_FILE"),
        }
        result = self._gcp_post(url, payload)
        body = result.get("body")
        if result.get("ok") and isinstance(body, dict):
            return {"ok": True, "key": body}
        return {"ok": False, "error": result.get("raw") or body}

    def _gcp_generate_id_token(
        self,
        service_account_email: str,
        *,
        audience: str = "",
        include_email: bool = True,
    ) -> Dict[str, Any]:
        payload: Dict[str, Any] = {"includeEmail": bool(include_email)}
        if audience:
            payload["audience"] = str(audience)
        encoded = quote(str(service_account_email).strip(), safe="")
        url = (
            "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/"
            f"{encoded}:generateIdToken"
        )
        result = self._gcp_post(url, payload)
        body = result.get("body")
        if result.get("ok") and isinstance(body, dict) and body.get("token"):
            return {
                "target": service_account_email,
                "success": True,
                "token": body.get("token"),
            }
        error = body if isinstance(body, dict) else (result.get("raw") or "")
        return {"target": service_account_email, "success": False, "error": error}

    @staticmethod
    def _gcp_append_ssh_metadata_entry(items, entry: str) -> List[dict]:
        items = [dict(item) for item in (items or [])]
        ssh_entry = None
        for item in items:
            if item.get("key") == "ssh-keys":
                ssh_entry = item
                break
        if ssh_entry is None:
            items.append({"key": "ssh-keys", "value": entry})
        else:
            existing = str(ssh_entry.get("value") or "").strip()
            lines = [line for line in existing.splitlines() if line.strip()]
            if entry not in lines:
                lines.append(entry)
            ssh_entry["value"] = "\n".join(lines)
        return items

    def _gcp_add_ssh_key_project_metadata(self, project_id: str, entry: str) -> Dict[str, Any]:
        encoded_project = self._quote_project(project_id)
        metadata_url = f"https://compute.googleapis.com/compute/v1/projects/{encoded_project}/commonInstanceMetadata"
        current = self._gcp_get(metadata_url)
        if not current.get("ok"):
            return {"ok": False, "error": current.get("raw") or "Failed to read project metadata"}

        body = current.get("body") or {}
        payload = {
            "items": self._gcp_append_ssh_metadata_entry(body.get("items"), entry),
            "fingerprint": body.get("fingerprint"),
        }
        set_url = f"https://compute.googleapis.com/compute/v1/projects/{encoded_project}/setCommonInstanceMetadata"
        result = self._gcp_post(set_url, payload)
        return {
            "ok": bool(result.get("ok")),
            "body": result.get("body"),
            "error": result.get("raw"),
        }

    def _gcp_add_ssh_key_instance_metadata(
        self, project_id: str, zone: str, instance_name: str, entry: str
    ) -> Dict[str, Any]:
        encoded_project = self._quote_project(project_id)
        encoded_zone = quote(str(zone).strip(), safe="")
        encoded_instance = quote(str(instance_name).strip(), safe="")
        get_url = (
            f"https://compute.googleapis.com/compute/v1/projects/{encoded_project}"
            f"/zones/{encoded_zone}/instances/{encoded_instance}"
        )
        current = self._gcp_get(get_url)
        if not current.get("ok"):
            return {"ok": False, "error": current.get("raw") or "Failed to read instance metadata"}

        instance = current.get("body") or {}
        metadata = dict(instance.get("metadata") or {})
        payload = {
            "items": self._gcp_append_ssh_metadata_entry(metadata.get("items"), entry),
            "fingerprint": metadata.get("fingerprint"),
        }
        set_url = (
            f"https://compute.googleapis.com/compute/v1/projects/{encoded_project}"
            f"/zones/{encoded_zone}/instances/{encoded_instance}/setMetadata"
        )
        result = self._gcp_post(set_url, payload)
        return {
            "ok": bool(result.get("ok")),
            "body": result.get("body"),
            "error": result.get("raw"),
            "instance": instance,
        }

    def _gcp_import_oslogin_ssh_key(
        self,
        user_email: str,
        public_key: str,
        *,
        key_type: str = "ssh-rsa",
        expiration_usec: Optional[str] = None,
    ) -> Dict[str, Any]:
        payload: Dict[str, Any] = {
            "key": str(public_key or "").strip(),
            "type": str(key_type or "ssh-rsa"),
        }
        if expiration_usec:
            payload["expirationTimeUsec"] = expiration_usec
        encoded_user = quote(str(user_email).strip(), safe="")
        url = f"https://oslogin.googleapis.com/v1/users/{encoded_user}:importSshPublicKey"
        result = self._gcp_post(url, payload)
        body = result.get("body")
        if result.get("ok") and isinstance(body, dict):
            return {"ok": True, "body": body}
        return {"ok": False, "error": result.get("raw") or body}

    @staticmethod
    def _gcp_oslogin_posix_username(login_profile: Any) -> str:
        if not isinstance(login_profile, dict):
            return ""
        profile = login_profile.get("loginProfile") if "loginProfile" in login_profile else login_profile
        if not isinstance(profile, dict):
            return ""
        for account in profile.get("posixAccounts") or []:
            username = str((account or {}).get("username") or "").strip()
            if username:
                return username
        return ""

    def _gcp_get_compute_instance(self, project_id: str, zone: str, instance_name: str) -> Dict[str, Any]:
        encoded_project = self._quote_project(project_id)
        encoded_zone = quote(str(zone).strip(), safe="")
        encoded_instance = quote(str(instance_name).strip(), safe="")
        url = (
            f"https://compute.googleapis.com/compute/v1/projects/{encoded_project}"
            f"/zones/{encoded_zone}/instances/{encoded_instance}"
        )
        result = self._gcp_get(url)
        body = result.get("body")
        if result.get("ok") and isinstance(body, dict):
            return {"ok": True, "instance": body}
        return {"ok": False, "error": result.get("raw") or body}

    def _gcp_instance_ip(self, instance: dict, *, internal: bool = False) -> str:
        if internal:
            interfaces = self._gcp_as_list((instance or {}).get("networkInterfaces"))
            if interfaces:
                return str(interfaces[0].get("networkIP") or "")
            return ""
        return self._gcp_instance_external_ip(instance)

    def _gcp_create_cloud_build(
        self,
        project_id: str,
        steps: List[dict],
        *,
        service_account: str = "",
        timeout: str = "600s",
        options: Optional[dict] = None,
    ) -> Dict[str, Any]:
        payload: Dict[str, Any] = {
            "steps": steps,
            "timeout": str(timeout or "600s"),
            "options": {"logging": "CLOUD_LOGGING_ONLY", **(options or {})},
        }
        sa = str(service_account or "").strip()
        if sa:
            if sa.startswith("projects/"):
                payload["serviceAccount"] = sa
            else:
                payload["serviceAccount"] = (
                    f"projects/{project_id}/serviceAccounts/{sa}"
                )
        url = f"https://cloudbuild.googleapis.com/v1/projects/{self._quote_project(project_id)}/builds"
        result = self._gcp_post(url, payload)
        body = result.get("body")
        if result.get("ok") and isinstance(body, dict):
            return {"ok": True, "build": body}
        return {"ok": False, "error": result.get("raw") or body}

    def _gcp_get_cloud_build(self, project_id: str, build_id: str) -> Dict[str, Any]:
        encoded = quote(str(build_id).strip(), safe="")
        url = (
            f"https://cloudbuild.googleapis.com/v1/projects/{self._quote_project(project_id)}"
            f"/builds/{encoded}"
        )
        result = self._gcp_get(url)
        body = result.get("body")
        if result.get("ok") and isinstance(body, dict):
            return {"ok": True, "build": body}
        return {"ok": False, "error": result.get("raw") or body}

    def _gcp_create_cloud_run_job(
        self,
        project_id: str,
        location: str,
        job_id: str,
        *,
        image: str,
        command: str,
        service_account: str = "",
        timeout_seconds: int = 300,
    ) -> Dict[str, Any]:
        container: Dict[str, Any] = {
            "image": str(image or "gcr.io/google.com/cloudsdktool/cloud-sdk:slim"),
            "command": ["/bin/bash", "-c"],
            "args": [str(command or "")],
        }
        template: Dict[str, Any] = {
            "template": {
                "containers": [container],
                "timeout": f"{max(1, int(timeout_seconds))}s",
            }
        }
        sa = str(service_account or "").strip()
        if sa:
            if sa.startswith("projects/"):
                template["template"]["serviceAccount"] = sa
            else:
                template["template"]["serviceAccount"] = (
                    f"projects/{project_id}/serviceAccounts/{sa}"
                )
        encoded_job = quote(str(job_id).strip(), safe="")
        url = (
            f"https://run.googleapis.com/v2/projects/{self._quote_project(project_id)}"
            f"/locations/{quote(str(location).strip(), safe='')}/jobs?jobId={encoded_job}"
        )
        result = self._gcp_post(url, template)
        body = result.get("body")
        if result.get("ok") and isinstance(body, dict):
            return {"ok": True, "job": body}
        return {"ok": False, "error": result.get("raw") or body}

    def _gcp_run_cloud_run_job(self, project_id: str, location: str, job_name: str) -> Dict[str, Any]:
        if str(job_name).startswith("projects/"):
            url = f"https://run.googleapis.com/v2/{str(job_name).strip()}:run"
        else:
            url = (
                f"https://run.googleapis.com/v2/projects/{self._quote_project(project_id)}"
                f"/locations/{quote(str(location).strip(), safe='')}/jobs/"
                f"{quote(str(job_name).strip(), safe='')}:run"
            )
        result = self._gcp_post(url, {})
        body = result.get("body")
        if result.get("ok") and isinstance(body, dict):
            return {"ok": True, "execution": body}
        return {"ok": False, "error": result.get("raw") or body}

    def _gcp_deploy_cloud_function_command(
        self,
        project_id: str,
        location: str,
        function_name: str,
        *,
        command: str,
        runtime: str = "python312",
        service_account: str = "",
        entry_point: str = "main",
    ) -> Dict[str, Any]:
        sa = str(service_account or "").strip()
        sa_flag = f"--service-account={sa}" if sa else ""
        deploy_cmd = (
            "set -euo pipefail; "
            "mkdir -p /workspace/fn && cd /workspace/fn && "
            "cat > main.py <<'EOF'\n"
            "import functions_framework\n"
            "import subprocess\n"
            f"@functions_framework.http\n"
            f"def {entry_point}(request):\n"
            f"    proc = subprocess.run({json.dumps(str(command or ''))}, shell=True, "
            "capture_output=True, text=True)\n"
            "    return (proc.stdout or proc.stderr or 'ok', 200, {'Content-Type': 'text/plain'})\n"
            "EOF\n"
            "cat > requirements.txt <<'EOF'\n"
            "functions-framework\n"
            "EOF\n"
            f"gcloud functions deploy {function_name} "
            f"--gen2 --runtime={runtime} --region={location} "
            f"--source=. --entry-point={entry_point} --trigger-http "
            f"--no-allow-unauthenticated {sa_flag} --quiet"
        )
        steps = [
            {
                "name": "gcr.io/cloud-builders/gcloud",
                "entrypoint": "bash",
                "args": ["-c", deploy_cmd],
            }
        ]
        build_result = self._gcp_create_cloud_build(
            project_id,
            steps,
            service_account=sa,
            timeout="1200s",
        )
        if not build_result.get("ok"):
            return build_result
        build = build_result.get("build") or {}
        return {
            "ok": True,
            "build": build,
            "function_name": function_name,
            "function_url_hint": (
                f"https://{location}-{project_id}.cloudfunctions.net/{function_name}"
            ),
        }

    @staticmethod
    def _gcp_pivot_listener_config(listener_module: str, options: dict) -> dict:
        return {
            "pivot_type": listener_module.rsplit("/", 1)[-1],
            "listener_module": listener_module,
            "options": options,
        }

    def _gcp_list_storage_hmac_keys(
        self, project_id: str, *, service_account_email: str = ""
    ) -> List[dict]:
        url = f"https://storage.googleapis.com/storage/v1/projects/{self._quote_project(project_id)}/hmacKeys"
        params: Dict[str, str] = {}
        sa = str(service_account_email or "").strip()
        if sa:
            params["serviceAccountEmail"] = sa
        return self._gcp_paginate_get(url, "items", max_items=100, params=params or None)

    def _gcp_cloud_sql_users(self, project_id: str, instance_name: str) -> List[dict]:
        quoted = self._quote_project(project_id)
        encoded = quote(str(instance_name).strip(), safe="")
        url = f"https://sqladmin.googleapis.com/v1/projects/{quoted}/instances/{encoded}/users"
        body = self._gcp_get_body(url)
        if isinstance(body, dict):
            return list(body.get("items") or [])
        return []

    def _gcp_cloud_sql_ssl_certs(self, project_id: str, instance_name: str) -> List[dict]:
        quoted = self._quote_project(project_id)
        encoded = quote(str(instance_name).strip(), safe="")
        url = f"https://sqladmin.googleapis.com/v1/projects/{quoted}/instances/{encoded}/sslCerts"
        body = self._gcp_get_body(url)
        if isinstance(body, dict):
            return list(body.get("items") or [])
        return []

    def _gcp_cloud_sql_instance(self, project_id: str, instance_name: str) -> Dict[str, Any]:
        quoted = self._quote_project(project_id)
        encoded = quote(str(instance_name).strip(), safe="")
        url = f"https://sqladmin.googleapis.com/v1/projects/{quoted}/instances/{encoded}"
        result = self._gcp_get(url)
        body = result.get("body")
        if result.get("ok") and isinstance(body, dict):
            return {"ok": True, "instance": body}
        return {"ok": False, "error": result.get("raw") or body}

    @staticmethod
    def _gcp_extract_build_source_refs(source: Any) -> List[dict]:
        if not isinstance(source, dict):
            return []
        refs: List[dict] = []
        mappings = [
            ("storageSource", "gcs"),
            ("repoSource", "cloud_source_repo"),
            ("gitSource", "git"),
            ("connectedRepository", "connected_repo"),
        ]
        for key, ref_type in mappings:
            value = source.get(key)
            if isinstance(value, dict) and value:
                refs.append({"type": ref_type, "details": value})
        developer = source.get("developerConnectConfig")
        if isinstance(developer, dict) and developer:
            refs.append({"type": "developer_connect", "details": developer})
        return refs

    @staticmethod
    def _gcp_artifact_registry_host(location: str) -> str:
        loc = str(location or "").strip()
        if not loc:
            return ""
        return f"{loc}-docker.pkg.dev"

    @staticmethod
    def _gcp_artifact_registry_pull_uri(
        location: str, project_id: str, repository: str, package: str, version: str = ""
    ) -> str:
        host = GcpPostMixin._gcp_artifact_registry_host(location)
        repo = str(repository or "").strip().strip("/")
        pkg = str(package or "").strip().strip("/")
        ver = str(version or "").strip().strip("/")
        if not host or not project_id or not repo:
            return ""
        base = f"{host}/{project_id}/{repo}/{pkg}"
        return f"{base}:{ver}" if ver else base

    def _gcp_list_firebase_rtdb_instances(self, project_id: str) -> List[dict]:
        url = (
            f"https://firebasedatabase.googleapis.com/v1beta1/projects/"
            f"{self._quote_project(project_id)}/locations/-/instances"
        )
        return self._gcp_paginate_get(url, "instances", max_items=50)

    def _gcp_firestore_list_collection_ids(self, parent: str) -> List[str]:
        parent = str(parent or "").strip()
        if not parent:
            return []
        if parent.startswith("https://"):
            parent = parent.split("/documents/", 1)[-1]
            parent = f"projects/{self._gcp_project_id()}/databases/(default)/documents/{parent}"
        if not parent.startswith("projects/"):
            project_id = self._gcp_project_id()
            parent = (
                f"projects/{self._quote_project(project_id)}/databases/(default)/documents/{parent}"
            )
        url = f"https://firestore.googleapis.com/v1/{parent}:listCollectionIds"
        result = self._gcp_post(url, {})
        body = result.get("body")
        if isinstance(body, dict):
            return list(body.get("collectionIds") or [])
        return []

    def _gcp_firestore_list_documents(self, collection_path: str, max_documents: int = 25) -> List[dict]:
        project_id = self._gcp_project_id()
        collection_path = str(collection_path or "").strip().strip("/")
        parent = (
            f"https://firestore.googleapis.com/v1/projects/{self._quote_project(project_id)}"
            f"/databases/(default)/documents/{collection_path}"
        )
        params = {"pageSize": min(max(1, max_documents), 300)}
        return self._gcp_paginate_get(parent, "documents", max_items=max_documents, params=params)

    def _gcp_firestore_recursive_dump(
        self,
        *,
        max_depth: int = 3,
        max_documents: int = 100,
        max_collections: int = 20,
        collection_filter: str = "",
    ) -> List[dict]:
        project_id = self._gcp_project_id()
        if not project_id:
            return []

        remaining_docs = max(1, int(max_documents))
        remaining_cols = max(1, int(max_collections))
        loot: List[dict] = []
        collection_filter = str(collection_filter or "").strip()

        def walk_collection(collection_path: str, depth: int) -> None:
            nonlocal remaining_docs, remaining_cols
            if remaining_docs <= 0 or remaining_cols <= 0 or depth > max(0, int(max_depth)):
                return

            batch_limit = min(remaining_docs, 25)
            documents = self._gcp_firestore_list_documents(collection_path, batch_limit)
            for document in documents:
                if remaining_docs <= 0:
                    return
                doc_name = str(document.get("name") or "")
                relative = doc_name.split("/documents/", 1)[-1] if "/documents/" in doc_name else doc_name
                loot.append(
                    {
                        "path": relative,
                        "depth": depth,
                        "fields": document.get("fields") or {},
                        "createTime": document.get("createTime"),
                        "updateTime": document.get("updateTime"),
                    }
                )
                remaining_docs -= 1

                if depth >= max(0, int(max_depth)):
                    continue
                for subcollection in self._gcp_firestore_list_collection_ids(doc_name):
                    if remaining_cols <= 0 or remaining_docs <= 0:
                        return
                    remaining_cols -= 1
                    walk_collection(f"{relative}/{subcollection}", depth + 1)

        if collection_filter:
            roots = [collection_filter.strip("/")]
        else:
            roots = list(self._gcp_body_dict("firestore_collections").get("collectionIds") or [])

        for root in roots:
            if remaining_cols <= 0 or remaining_docs <= 0:
                break
            remaining_cols -= 1
            walk_collection(root.strip("/"), 0)
        return loot

    def _gcp_rtdb_fetch_json(self, database_url: str, path: str = "", shallow: bool = False) -> Dict[str, Any]:
        base = str(database_url or "").strip().rstrip("/")
        if not base:
            return {"ok": False, "error": "missing database_url"}
        suffix = str(path or "").strip().strip("/")
        url = f"{base}/{suffix}.json" if suffix else f"{base}/.json"
        if shallow:
            url = f"{url}?shallow=true"
        result = self._gcp_get(url)
        body = result.get("body")
        if result.get("ok"):
            return {"ok": True, "data": body, "url": url}
        return {"ok": False, "error": result.get("raw") or body, "url": url}

    def _gcp_project_ancestry(self, project_id: str) -> List[dict]:
        url = (
            f"https://cloudresourcemanager.googleapis.com/v1/projects/"
            f"{self._quote_project(project_id)}:getAncestry"
        )
        result = self._gcp_post(url, {})
        body = result.get("body")
        if result.get("ok") and isinstance(body, dict):
            return list(body.get("ancestor") or [])
        return []

    def _gcp_get_resource_iam_policy(self, resource_name: str) -> Dict[str, Any]:
        resource_name = str(resource_name or "").strip().strip("/")
        if not resource_name:
            return {"ok": False, "error": "missing resource_name"}
        if not resource_name.startswith(("projects/", "folders/", "organizations/")):
            return {"ok": False, "error": "unsupported resource prefix"}
        url = f"https://cloudresourcemanager.googleapis.com/v1/{resource_name}:getIamPolicy"
        if resource_name.startswith("folders/"):
            url = f"https://cloudresourcemanager.googleapis.com/v2/{resource_name}:getIamPolicy"
        result = self._gcp_post(url, {})
        body = result.get("body")
        if result.get("ok") and isinstance(body, dict):
            return {"ok": True, "policy": body}
        return {"ok": False, "error": result.get("raw") or body}

    def _gcp_list_deny_policies(self, parent: str) -> List[dict]:
        parent = str(parent or "").strip().strip("/")
        if not parent:
            return []
        if not parent.startswith(("projects/", "folders/", "organizations/")):
            parent = f"projects/{self._quote_project(parent)}/locations/global"
        elif parent.startswith("projects/") and "/locations/" not in parent:
            parent = f"{parent}/locations/global"
        url = f"https://iam.googleapis.com/v2/{parent}/policies"
        return self._gcp_paginate_get(url, "policies", max_items=50)

    def _gcp_list_workload_identity_pools(self, project_id: str) -> List[dict]:
        quoted = self._quote_project(project_id)
        url = f"https://iam.googleapis.com/v1/projects/{quoted}/locations/global/workloadIdentityPools"
        return self._gcp_paginate_get(url, "workloadIdentityPools", max_items=50)

    def _gcp_list_workload_identity_providers(self, project_id: str, pool_id: str) -> List[dict]:
        quoted = self._quote_project(project_id)
        pool = quote(str(pool_id).strip(), safe="")
        url = (
            f"https://iam.googleapis.com/v1/projects/{quoted}/locations/global/"
            f"workloadIdentityPools/{pool}/providers"
        )
        return self._gcp_paginate_get(url, "workloadIdentityProviders", max_items=50)

    def _gcp_collect_service_account_attachments(self, project_id: str) -> Dict[str, List[dict]]:
        attachments: Dict[str, List[dict]] = {}
        for instance in self._flatten_compute_instances(self._gcp_body("compute_instances")):
            sa_email = self._gcp_instance_service_account(instance)
            if not sa_email:
                continue
            attachments.setdefault(sa_email, []).append(
                {
                    "type": "compute_instance",
                    "name": instance.get("name"),
                    "zone": str(instance.get("zone") or "").rsplit("/", 1)[-1],
                    "external_ip": self._gcp_instance_external_ip(instance),
                }
            )
        for service in list(self._gcp_body_dict("cloud_run_jobs").get("jobs") or []):
            template = ((service.get("template") or {}).get("template") or {})
            sa_email = str(template.get("serviceAccount") or "").rsplit("/", 1)[-1]
            if "@" not in sa_email:
                sa_email = template.get("serviceAccount") or ""
            if sa_email:
                attachments.setdefault(sa_email, []).append(
                    {"type": "cloud_run_job", "name": str(service.get("name") or "")}
                )
        for fn in list(self._gcp_body_dict("functions_v2").get("functions") or []):
            sa_email = str((fn.get("serviceConfig") or {}).get("serviceAccountEmail") or "")
            if sa_email:
                attachments.setdefault(sa_email, []).append(
                    {"type": "cloud_function_v2", "name": str(fn.get("name") or "")}
                )
        for fn in list(self._gcp_body_dict("functions_v1").get("functions") or []):
            sa_email = str(fn.get("serviceAccountEmail") or "")
            if sa_email:
                attachments.setdefault(sa_email, []).append(
                    {"type": "cloud_function_v1", "name": str(fn.get("name") or "")}
                )
        return attachments

    def _gcp_members_can_impersonate_sa(
        self, project_id: str, service_account_email: str
    ) -> List[dict]:
        encoded = quote(str(service_account_email).strip(), safe="")
        url = (
            f"https://iam.googleapis.com/v1/projects/{self._quote_project(project_id)}"
            f"/serviceAccounts/{encoded}:getIamPolicy"
        )
        result = self._gcp_post(url, {})
        body = result.get("body")
        if not result.get("ok") or not isinstance(body, dict):
            return []
        impersonation_roles = {
            "roles/iam.serviceAccountTokenCreator",
            "roles/iam.serviceAccountUser",
            "roles/owner",
            "roles/editor",
        }
        grants: List[dict] = []
        for binding in body.get("bindings") or []:
            role = str(binding.get("role") or "")
            if role not in impersonation_roles and "serviceAccountTokenCreator" not in role:
                continue
            for member in binding.get("members") or []:
                grants.append({"member": member, "role": role})
        return grants

    def _gcp_build_attack_graph(
        self,
        *,
        principal: str,
        include_network: bool = True,
        include_exposure: bool = True,
        max_service_accounts: int = 40,
    ) -> Dict[str, Any]:
        project_id = self._gcp_project_id()
        nodes: List[dict] = []
        edges: List[dict] = []
        node_ids: Set[str] = set()

        def add_node(node_id: str, node_type: str, label: str, **meta):
            if node_id in node_ids:
                return
            node_ids.add(node_id)
            nodes.append({"id": node_id, "type": node_type, "label": label, **meta})

        def add_edge(source: str, target: str, relationship: str, **meta):
            edges.append({"from": source, "to": target, "relationship": relationship, **meta})

        principal_id = f"principal:{principal}"
        add_node(principal_id, "principal", principal, email=principal)

        bindings = self._gcp_iam_bindings()
        roles = self._gcp_roles_for_member(principal, bindings=bindings)
        for role in roles:
            role_id = f"role:{role}"
            add_node(role_id, "role", role)
            add_edge(principal_id, role_id, "has_project_role")

        effective = self._gcp_collect_effective_permissions(principal, bindings=bindings)
        for path in self._gcp_identify_privesc_paths(effective["permissions"], principal):
            path_id = f"path:{path.get('id')}"
            add_node(path_id, "privesc_path", path.get("name", path.get("id")), severity=path.get("severity"))
            add_edge(principal_id, path_id, "privesc_path")

        attachments = self._gcp_collect_service_account_attachments(project_id)
        sa_data = list(self._gcp_body_dict("service_accounts").get("accounts") or [])[:max_service_accounts]
        for account in sa_data:
            email = str(account.get("email") or "")
            if not email:
                continue
            sa_id = f"serviceAccount:{email}"
            add_node(sa_id, "service_account", email, disabled=account.get("disabled"))
            sa_roles = self._gcp_roles_for_member(email, bindings=bindings)
            for role in sa_roles:
                role_id = f"role:{role}"
                add_node(role_id, "role", role)
                add_edge(sa_id, role_id, "has_project_role")
            for grant in self._gcp_members_can_impersonate_sa(project_id, email):
                member = str(grant.get("member") or "")
                if principal.lower() in member.lower():
                    add_edge(principal_id, sa_id, "can_impersonate", role=grant.get("role"))
            for resource in attachments.get(email, []):
                resource_id = f"{resource.get('type')}:{resource.get('name')}"
                add_node(resource_id, resource.get("type", "resource"), str(resource.get("name") or ""))
                add_edge(sa_id, resource_id, "runs_as")

        if include_exposure:
            for finding in self._gcp_public_bindings(bindings):
                exposure_id = f"exposure:project_iam:{finding.get('role')}"
                add_node(exposure_id, "public_exposure", finding.get("role", "public"))
                add_edge(principal_id, exposure_id, "public_exposure", members=finding.get("members"))

        if include_network:
            for rule in list(self._gcp_body_dict("compute_firewalls").get("items") or []):
                if not isinstance(rule, dict):
                    continue
                if rule.get("disabled") or not self._gcp_firewall_is_public_source(rule.get("sourceRanges")):
                    continue
                rule_id = f"firewall:{rule.get('name')}"
                add_node(rule_id, "network_path", str(rule.get("name") or ""))
                add_edge(principal_id, rule_id, "network_entry")

        return {"project_id": project_id, "principal": principal, "nodes": nodes, "edges": edges}
