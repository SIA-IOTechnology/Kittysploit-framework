#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json

from kittysploit import *
from lib.post.gcp import GcpPostMixin


class Module(Post, GcpPostMixin):
    __info__ = {
        "name": "GCP Workload Identity Federation",
        "description": "Analyze workload identity pools, providers, and risky federation configurations",
        "author": "KittySploit Team",
        "version": "1.0.0",
        "session_type": SessionType.GCP_API,
        "tags": ["gcp", "iam", "workload-identity", "federation", "cloud"],
        "references": [
            "https://cloud.google.com/iam/docs/workload-identity-federation",
        ],
    'agent': {
        'risk': 'intrusive',
        'effects': ['api_request'],
        'expected_requests': 10,
        'reversible': False,
        'approval_required': True,
        'produces': ['risk_signals'],
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
        'chain':         {'produces_capabilities': [],
         'consumes_capabilities': ['shell'],
         'option_bindings': {},
         'suggested_followups': []},
    },
    }

    max_pools = OptInteger(20, "Maximum workload identity pools to inspect", False)
    include_providers = OptBool(True, "Inspect providers for each pool", False)
    flag_disabled = OptBool(True, "Flag disabled pools or providers", False)
    export_json = OptString("", "Optional JSON output file", False)
    verbose = OptBool(False, "Show provider configuration details", False)

    def run(self):
        try:
            print_info("Analyzing GCP Workload Identity Federation...")
            project_id = self._gcp_project_id()
            if not project_id:
                print_error("Could not resolve project_id from session")
                return False

            print_info(f"Project: {project_id}")
            print_info("=" * 80)

            pools = self._gcp_list_workload_identity_pools(project_id)[: max(1, int(self.max_pools or 20))]
            if not pools:
                print_warning("No workload identity pools found")
                payload = {"project_id": project_id, "pools": [], "findings": []}
                return self.module_result(success=True, data=payload)

            findings = []
            analyzed = []
            for pool in pools:
                pool_name = str(pool.get("name") or "")
                pool_id = pool_name.rsplit("/", 1)[-1]
                entry = {
                    "name": pool_id,
                    "full_name": pool_name,
                    "state": pool.get("state"),
                    "displayName": pool.get("displayName"),
                    "description": pool.get("description"),
                    "disabled": pool.get("disabled"),
                    "providers": [],
                }
                print_info(f"Pool: {pool_id} state={pool.get('state')} disabled={pool.get('disabled')}")

                if self.flag_disabled and pool.get("disabled"):
                    findings.append(
                        {"severity": "MEDIUM", "pool": pool_id, "issue": "Workload identity pool is disabled"}
                    )

                if self.include_providers:
                    providers = self._gcp_list_workload_identity_providers(project_id, pool_id)
                    for provider in providers:
                        provider_entry = self._analyze_provider(provider, pool_id=pool_id)
                        entry["providers"].append(provider_entry)
                        print_info(
                            f"  provider: {provider_entry.get('name')} "
                            f"type={provider_entry.get('provider_type')} "
                            f"state={provider_entry.get('state')}"
                        )
                        findings.extend(provider_entry.pop("findings", []))
                        if self.verbose:
                            print_info(json.dumps(provider_entry, ensure_ascii=False)[:1000])

                analyzed.append(entry)
                print_info("-" * 80)

            payload = {"project_id": project_id, "pools": analyzed, "findings": findings}
            print_info("=" * 80)
            if findings:
                print_warning(f"Found {len(findings)} federation note(s)")
                for item in findings[:20]:
                    print_warning(f"  [{item.get('severity')}] {item.get('pool')} / {item.get('provider', '-')} : {item.get('issue')}")
            else:
                print_success("No notable workload identity federation misconfigurations detected")

            exported = self._gcp_export_json(self.export_json, payload) if self.export_json else ""
            if exported:
                print_success(f"Results exported to {exported}")
            return self.module_result(success=True, data=payload)
        except Exception as exc:
            print_error(f"Workload identity federation analysis failed: {exc}")
            return False

    def _analyze_provider(self, provider, pool_id=""):
        name = str(provider.get("name") or "").rsplit("/", 1)[-1]
        provider_type = "unknown"
        config = {}
        findings = []
        for key in ("oidc", "aws", "saml"):
            if provider.get(key):
                provider_type = key
                config = provider.get(key) or {}
                break

        entry = {
            "name": name,
            "full_name": provider.get("name"),
            "state": provider.get("state"),
            "disabled": provider.get("disabled"),
            "provider_type": provider_type,
            "attributeMapping": provider.get("attributeMapping") or {},
            "attributeCondition": provider.get("attributeCondition"),
            "config": config,
        }

        if provider.get("disabled"):
            findings.append(
                {"severity": "LOW", "pool": pool_id, "provider": name, "issue": "Provider is disabled"}
            )
        if provider_type == "oidc":
            issuer = config.get("issuerUri") or config.get("issuer")
            if issuer:
                entry["issuer"] = issuer
            allowed_audiences = config.get("allowedAudiences") or []
            entry["allowedAudiences"] = allowed_audiences
            if not allowed_audiences:
                findings.append(
                    {
                        "severity": "HIGH",
                        "pool": pool_id,
                        "provider": name,
                        "issue": "OIDC provider has no allowedAudiences restriction",
                    }
                )
        if provider_type == "aws":
            account_id = config.get("accountId")
            if account_id:
                entry["aws_account_id"] = account_id
        condition = str(provider.get("attributeCondition") or "")
        if not condition:
            findings.append(
                {
                    "severity": "MEDIUM",
                    "pool": pool_id,
                    "provider": name,
                    "issue": "No attributeCondition restricting federated identities",
                }
            )
        entry["findings"] = findings
        return entry
