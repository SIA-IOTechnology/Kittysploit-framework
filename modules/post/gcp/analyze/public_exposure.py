#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
from lib.post.gcp import GcpPostMixin


class Module(Post, GcpPostMixin):
    __info__ = {
        "name": "GCP Public Exposure",
        "description": "Detect publicly exposed GCP resources (IAM, storage, firewalls, SQL, BigQuery)",
        "author": "KittySploit Team",
        "version": "1.0.0",
        "session_type": SessionType.GCP_API,
        "tags": ["gcp", "exposure", "misconfiguration", "cloud"],
        "references": [
            "https://cloud.google.com/iam/docs/principal-identifiers",
            "https://attack.mitre.org/techniques/T1190/",
        ],
    'agent': {
        'risk': 'intrusive',
        'effects': ['api_request'],
        'expected_requests': 12,
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

    check_project_iam = OptBool(True, "Check project IAM for allUsers/allAuthenticatedUsers", False)
    check_storage = OptBool(True, "Check Cloud Storage bucket IAM exposure", False)
    check_firewalls = OptBool(True, "Check Compute firewalls with 0.0.0.0/0 ingress", False)
    check_sql = OptBool(True, "Check Cloud SQL public authorized networks", False)
    check_bigquery = OptBool(True, "Check BigQuery dataset ACL exposure", False)
    max_buckets = OptString("25", "Maximum buckets to inspect", False)
    export_json = OptString("", "Optional JSON output file", False)
    verbose = OptBool(False, "Show additional diagnostic output", False)

    def run(self):
        try:
            print_info("Starting GCP public exposure analysis...")
            project_id = self._gcp_project_id()
            principal = self._gcp_client_email()
            print_info(f"Project: {project_id or 'unknown'}")
            if principal:
                print_info(f"Principal: {principal}")
            print_info("=" * 80)

            findings = {
                "project_id": project_id,
                "principal": principal,
                "project_iam": [],
                "storage": [],
                "firewalls": [],
                "sql": [],
                "bigquery": [],
            }
            if self.check_project_iam:
                findings["project_iam"] = self._check_project_iam()
            if self.check_storage:
                findings["storage"] = self._check_storage(project_id)
            if self.check_firewalls:
                findings["firewalls"] = self._check_firewalls()
            if self.check_sql:
                findings["sql"] = self._check_sql()
            if self.check_bigquery:
                findings["bigquery"] = self._check_bigquery(project_id)

            total = sum(len(findings[key]) for key in ("project_iam", "storage", "firewalls", "sql", "bigquery"))
            print_info("=" * 80)
            if total == 0:
                print_success("No public exposure findings detected in selected checks")
            else:
                print_warning(f"Total public exposure findings: {total}")

            exported = self._gcp_export_json(self.export_json, findings) if self.export_json else ""
            if exported:
                print_success(f"Results exported to {exported}")
            return True
        except Exception as exc:
            print_error(f"Error during GCP public exposure analysis: {exc}")
            return False

    def _check_project_iam(self):
        findings = self._gcp_public_bindings()
        print_status("Check: project IAM public bindings")
        if not findings:
            print_success("No allUsers/allAuthenticatedUsers bindings on project IAM")
        else:
            print_error(f"Found {len(findings)} public project IAM binding(s)")
            for item in findings:
                print_warning(f"  role={item['role']} members={', '.join(item['members'])}")
        print_info("-" * 80)
        return findings

    def _check_storage(self, project_id):
        print_status("Check: Cloud Storage bucket IAM")
        limit = self._gcp_to_int(self.max_buckets, 25)
        buckets = list((self._gcp_body_dict("storage_buckets").get("items") or []))[:limit]
        findings = []
        for bucket in buckets:
            name = self._gcp_bucket_name(bucket)
            if not name:
                continue
            policy = self._gcp_get_body(f"https://storage.googleapis.com/storage/v1/b/{name}/iam")
            if not isinstance(policy, dict):
                continue
            public_bindings = []
            for binding in policy.get("bindings") or []:
                members = [m for m in binding.get("members") or [] if self._gcp_is_public_member(m)]
                if members:
                    public_bindings.append({"role": binding.get("role", ""), "members": members})
            if public_bindings:
                findings.append({"bucket": name, "bindings": public_bindings})
                print_error(f"  Public bucket IAM: {name}")
        if not findings:
            print_success(f"No public bucket IAM found in {len(buckets)} inspected bucket(s)")
        else:
            print_warning(f"Found {len(findings)} publicly exposed bucket(s)")
        print_info("-" * 80)
        return findings

    def _check_firewalls(self):
        print_status("Check: Compute firewall ingress from Internet")
        rules = list(self._gcp_body_dict("compute_firewalls").get("items") or [])
        findings = []
        for rule in rules:
            if rule.get("disabled") or str(rule.get("direction", "INGRESS")).upper() != "INGRESS":
                continue
            if "0.0.0.0/0" not in self._gcp_as_list(rule.get("sourceRanges")):
                continue
            findings.append(
                {
                    "name": rule.get("name", ""),
                    "network": rule.get("network", ""),
                    "allowed": rule.get("allowed"),
                    "source_ranges": rule.get("sourceRanges"),
                }
            )
            print_warning(f"  Internet-facing firewall: {rule.get('name')}")
        if not findings:
            print_success("No 0.0.0.0/0 ingress firewall rules found")
        else:
            print_error(f"Found {len(findings)} Internet-exposed firewall rule(s)")
        print_info("-" * 80)
        return findings

    def _check_sql(self):
        print_status("Check: Cloud SQL authorized networks")
        instances = list(self._gcp_body_dict("sql_instances").get("items") or [])
        findings = []
        for instance in instances:
            ip_config = ((instance.get("settings") or {}).get("ipConfiguration")) or {}
            authorized = list(ip_config.get("authorizedNetworks") or [])
            if ip_config.get("ipv4Enabled") and (not authorized or any(
                str(net.get("value", "")).startswith("0.0.0.0") for net in authorized
            )):
                name = instance.get("name", "")
                findings.append({"name": name, "authorized_networks": authorized})
                print_warning(f"  Cloud SQL may be Internet-reachable: {name}")
        if not findings:
            print_success("No obviously public Cloud SQL instances found")
        else:
            print_error(f"Found {len(findings)} Cloud SQL exposure finding(s)")
        print_info("-" * 80)
        return findings

    def _check_bigquery(self, project_id):
        print_status("Check: BigQuery dataset ACLs")
        datasets = list(self._gcp_body_dict("bigquery_datasets").get("datasets") or [])
        findings = []
        for dataset in datasets:
            dataset_id = (dataset.get("datasetReference") or {}).get("datasetId", "")
            if not dataset_id:
                continue
            detail = self._gcp_get_body(
                f"https://bigquery.googleapis.com/v2/projects/{project_id}/datasets/{dataset_id}"
            )
            if not isinstance(detail, dict):
                continue
            public_entries = []
            for entry in detail.get("access") or []:
                for key in ("specialGroup", "iamMember", "userByEmail"):
                    if self._gcp_is_public_member(entry.get(key)):
                        public_entries.append(entry)
            if public_entries:
                findings.append({"dataset": dataset_id, "access": public_entries})
                print_error(f"  Public BigQuery dataset ACL: {dataset_id}")
        if not findings:
            print_success("No public BigQuery dataset ACLs found")
        else:
            print_warning(f"Found {len(findings)} public BigQuery dataset(s)")
        print_info("-" * 80)
        return findings
