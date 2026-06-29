#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import os
import time
from urllib.parse import quote

import requests
from kittysploit import *


DEFAULT_SCOPES = (
    "https://www.googleapis.com/auth/cloud-platform",
    "https://www.googleapis.com/auth/datastore",
    "https://www.googleapis.com/auth/devstorage.read_only",
)


class GcpApiConsoleConnection:
    def __init__(self, project_id, token, client_email="", scopes=None, timeout=30):
        self.project_id = project_id
        self.token = token
        self.client_email = client_email
        self.scopes = scopes or list(DEFAULT_SCOPES)
        self.timeout = int(timeout or 30)

    def _headers(self):
        return {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json",
        }

    def request(self, method, url, payload=None, params=None):
        method = method.upper()
        kwargs = {
            "headers": self._headers(),
            "params": params,
            "timeout": self.timeout,
        }
        if payload is not None:
            kwargs["json"] = payload
        response = requests.request(method, url, **kwargs)
        try:
            body = response.json()
        except Exception:
            body = response.text
        return {
            "status_code": response.status_code,
            "ok": response.ok,
            "body": body,
            "url": response.url,
        }

    def _format_response(self, result):
        body = result.get("body")
        if isinstance(body, (dict, list)):
            rendered = json.dumps(body, indent=2, ensure_ascii=False)
        else:
            rendered = str(body or "")
        status = result.get("status_code")
        url = result.get("url", "")
        return f"HTTP {status} {url}\n{rendered}"

    def _project_url(self, api_path):
        return api_path.format(project_id=quote(self.project_id, safe=""))

    def run_command(self, command):
        command = (command or "").strip()
        if not command:
            return ""
        parts = command.split()
        cmd = parts[0].lower()
        args = parts[1:]

        if cmd in ("help", "?"):
            return self.help_text()
        if cmd == "whoami":
            return json.dumps(
                {
                    "project_id": self.project_id,
                    "client_email": self.client_email,
                    "scopes": self.scopes,
                },
                indent=2,
                ensure_ascii=False,
            )
        if cmd == "get":
            if not args:
                return "Usage: get <absolute_url>"
            return self._format_response(self.request("GET", args[0]))
        if cmd == "post":
            if not args:
                return "Usage: post <absolute_url> [json_payload]"
            payload = json.loads(" ".join(args[1:])) if len(args) > 1 else {}
            return self._format_response(self.request("POST", args[0], payload=payload))
        if cmd == "audit":
            return self._run_audit(args)

        route = self._routes().get(cmd)
        if not route:
            return f"Unknown command: {cmd}\n\n{self.help_text()}"

        method, url, payload, params = route(args)
        return self._format_response(self.request(method, url, payload=payload, params=params))

    def _run_audit(self, args):
        include_heavy = "--heavy" in args
        commands = [
            "project",
            "iam_policy",
            "enabled_services",
            "service_accounts",
            "storage_buckets",
            "compute_firewalls",
            "cloud_run_locations",
            "functions_v1",
            "functions_v2",
            "secrets",
            "artifact_repos",
            "cloud_builds",
            "pubsub_topics",
            "pubsub_subscriptions",
            "sql_instances",
            "bigquery_datasets",
            "firestore_collections",
            "firestore_indexes",
            "firebase_apps",
            "firebase_sites",
            "firebase_rules",
            "remote_config",
            "api_keys",
            "logs",
        ]
        if include_heavy:
            commands.extend(["compute_instances", "gke_clusters"])

        results = []
        for name in commands:
            method, url, payload, params = self._routes()[name]([])
            try:
                result = self.request(method, url, payload=payload, params=params)
                results.append(
                    {
                        "name": name,
                        "status_code": result.get("status_code"),
                        "ok": result.get("ok"),
                        "url": result.get("url"),
                        "body": result.get("body"),
                    }
                )
            except Exception as exc:
                results.append({"name": name, "error": str(exc)})

        summary = {}
        for item in results:
            key = str(item.get("status_code") or "error")
            summary[key] = summary.get(key, 0) + 1
        return json.dumps(
            {
                "project_id": self.project_id,
                "client_email": self.client_email,
                "started_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "include_heavy": include_heavy,
                "summary": summary,
                "results": results,
            },
            indent=2,
            ensure_ascii=False,
        )

    def _routes(self):
        p = quote(self.project_id, safe="")
        parent_docs = f"projects/{p}/databases/(default)/documents"

        return {
            "project": lambda _a: (
                "GET",
                f"https://cloudresourcemanager.googleapis.com/v1/projects/{p}",
                None,
                None,
            ),
            "iam_policy": lambda _a: (
                "POST",
                f"https://cloudresourcemanager.googleapis.com/v1/projects/{p}:getIamPolicy",
                {},
                None,
            ),
            "enabled_services": lambda _a: (
                "GET",
                f"https://serviceusage.googleapis.com/v1/projects/{p}/services",
                None,
                {"filter": "state:ENABLED", "pageSize": 200},
            ),
            "service_accounts": lambda _a: (
                "GET",
                f"https://iam.googleapis.com/v1/projects/{p}/serviceAccounts",
                None,
                None,
            ),
            "storage_buckets": lambda _a: (
                "GET",
                f"https://storage.googleapis.com/storage/v1/b?project={p}",
                None,
                None,
            ),
            "compute_instances": lambda _a: (
                "GET",
                f"https://compute.googleapis.com/compute/v1/projects/{p}/aggregated/instances",
                None,
                {"maxResults": 50},
            ),
            "compute_firewalls": lambda _a: (
                "GET",
                f"https://compute.googleapis.com/compute/v1/projects/{p}/global/firewalls",
                None,
                {"maxResults": 50},
            ),
            "gke_clusters": lambda _a: (
                "GET",
                f"https://container.googleapis.com/v1/projects/{p}/aggregated/clusters",
                None,
                {"maxResults": 30},
            ),
            "cloud_run_locations": lambda _a: (
                "GET",
                f"https://run.googleapis.com/v1/projects/{p}/locations",
                None,
                None,
            ),
            "cloud_run_jobs": lambda _a: (
                "GET",
                f"https://run.googleapis.com/v2/projects/{p}/locations/-/jobs",
                None,
                None,
            ),
            "functions_v1": lambda _a: (
                "GET",
                f"https://cloudfunctions.googleapis.com/v1/projects/{p}/locations/-/functions",
                None,
                None,
            ),
            "functions_v2": lambda _a: (
                "GET",
                f"https://cloudfunctions.googleapis.com/v2/projects/{p}/locations/-/functions",
                None,
                None,
            ),
            "secrets": lambda _a: (
                "GET",
                f"https://secretmanager.googleapis.com/v1/projects/{p}/secrets",
                None,
                None,
            ),
            "artifact_repos": lambda _a: (
                "GET",
                f"https://artifactregistry.googleapis.com/v1/projects/{p}/locations/-/repositories",
                None,
                None,
            ),
            "cloud_builds": lambda _a: (
                "GET",
                f"https://cloudbuild.googleapis.com/v1/projects/{p}/builds",
                None,
                {"pageSize": 20},
            ),
            "pubsub_topics": lambda _a: (
                "GET",
                f"https://pubsub.googleapis.com/v1/projects/{p}/topics",
                None,
                None,
            ),
            "pubsub_subscriptions": lambda _a: (
                "GET",
                f"https://pubsub.googleapis.com/v1/projects/{p}/subscriptions",
                None,
                None,
            ),
            "sql_instances": lambda _a: (
                "GET",
                f"https://sqladmin.googleapis.com/v1/projects/{p}/instances",
                None,
                None,
            ),
            "bigquery_datasets": lambda _a: (
                "GET",
                f"https://bigquery.googleapis.com/v2/projects/{p}/datasets",
                None,
                None,
            ),
            "firestore_collections": lambda _a: (
                "POST",
                f"https://firestore.googleapis.com/v1/projects/{p}/databases/(default)/documents:listCollectionIds",
                {"parent": parent_docs},
                None,
            ),
            "firestore_indexes": lambda _a: (
                "GET",
                f"https://firestore.googleapis.com/v1/projects/{p}/databases/(default)/collectionGroups/-/indexes",
                None,
                None,
            ),
            "firebase_apps": lambda _a: (
                "GET",
                f"https://firebase.googleapis.com/v1beta1/projects/{p}/webApps",
                None,
                None,
            ),
            "firebase_sites": lambda _a: (
                "GET",
                f"https://firebasehosting.googleapis.com/v1beta1/projects/{p}/sites",
                None,
                None,
            ),
            "firebase_rules": lambda _a: (
                "GET",
                f"https://firebaserules.googleapis.com/v1/projects/{p}/releases",
                None,
                None,
            ),
            "remote_config": lambda _a: (
                "GET",
                f"https://firebaseremoteconfig.googleapis.com/v1/projects/{p}/remoteConfig",
                None,
                None,
            ),
            "api_keys": lambda _a: (
                "GET",
                f"https://apikeys.googleapis.com/v2/projects/{p}/locations/global/keys",
                None,
                None,
            ),
            "logs": lambda _a: (
                "GET",
                f"https://logging.googleapis.com/v2/projects/{p}/logs",
                None,
                {"pageSize": 50},
            ),
        }

    def help_text(self):
        commands = [
            "whoami",
            "audit [--heavy]",
            "project",
            "iam_policy",
            "enabled_services",
            "service_accounts",
            "storage_buckets",
            "compute_instances",
            "compute_firewalls",
            "gke_clusters",
            "cloud_run_locations",
            "cloud_run_jobs",
            "functions_v1",
            "functions_v2",
            "secrets",
            "artifact_repos",
            "cloud_builds",
            "pubsub_topics",
            "pubsub_subscriptions",
            "sql_instances",
            "bigquery_datasets",
            "firestore_collections",
            "firestore_indexes",
            "firebase_apps",
            "firebase_sites",
            "firebase_rules",
            "remote_config",
            "api_keys",
            "logs",
            "get <url>",
            "post <url> [json_payload]",
        ]
        return "Available GCP API commands:\n" + "\n".join(f"  {c}" for c in commands)


class Module(Listener):
    __info__ = {
        "name": "Google Cloud API Console Listener",
        "description": "Creates an interactive GCP/Firebase API console from a token or service account.",
        "author": "KittySploit Team",
        "version": "1.0.0",
        "handler": Handler.BIND,
        "session_type": "gcp_api",
        "protocol": "gcp_api",
        "dependencies": [],
        "optional_dependencies": ["google-auth"],
    }

    project_id = OptString("", "Google Cloud project ID; inferred from service account when empty", False)
    service_account_file = OptString("service-account.json", "Google service account JSON key file", False)
    service_account_json = OptString("", "Raw Google service account JSON key", False, advanced=True)
    access_token = OptString("", "Raw OAuth2 access token", False, advanced=True)
    access_token_file = OptString("", "File containing an OAuth2 access token", False, advanced=True)
    auth_scopes = OptString(",".join(DEFAULT_SCOPES), "Comma-separated OAuth scopes", False, advanced=True)
    test_command = OptString("whoami", "Command used to verify the API console", False)
    timeout = OptInteger(30, "HTTP/API timeout in seconds", False, advanced=True)

    @staticmethod
    def _as_str(value):
        raw = getattr(value, "value", value)
        return str(raw or "").strip()

    @staticmethod
    def _normalize_service_account_info(info):
        if not isinstance(info, dict):
            return info
        private_key = info.get("private_key")
        if isinstance(private_key, str) and "\\n" in private_key:
            info = dict(info)
            info["private_key"] = private_key.replace("\\n", "\n")
        return info

    def _scopes(self):
        scopes = [scope.strip() for scope in self._as_str(self.auth_scopes).split(",") if scope.strip()]
        return scopes or list(DEFAULT_SCOPES)

    def _load_service_account(self):
        raw_json = self._as_str(self.service_account_json)
        if raw_json:
            return self._normalize_service_account_info(json.loads(raw_json))
        path = self._as_str(self.service_account_file)
        if path and os.path.isfile(path):
            with open(path, "r", encoding="utf-8") as handle:
                return self._normalize_service_account_info(json.load(handle))
        return None

    def _token_from_service_account(self, info):
        try:
            from google.auth.transport.requests import Request
            from google.oauth2 import service_account
        except ImportError:
            print_error("google-auth is required for service account authentication")
            return "", ""
        credentials = service_account.Credentials.from_service_account_info(info, scopes=self._scopes())
        credentials.refresh(Request())
        return credentials.token or "", info.get("client_email", "")

    def _resolve_token(self):
        token = self._as_str(self.access_token)
        if token:
            return token, "", self._as_str(self.project_id)
        token_file = self._as_str(self.access_token_file)
        if token_file:
            with open(token_file, "r", encoding="utf-8") as handle:
                return handle.read().strip(), "", self._as_str(self.project_id)
        info = self._load_service_account()
        if info:
            token, email = self._token_from_service_account(info)
            project_id = self._as_str(self.project_id) or str(info.get("project_id") or "")
            return token, email, project_id
        print_error("Set access_token, access_token_file, service_account_file, or service_account_json")
        return "", "", self._as_str(self.project_id)

    def run(self, background=False):
        token, client_email, project_id = self._resolve_token()
        if not token:
            return False
        if not project_id:
            print_error("project_id is required when it cannot be inferred from service account JSON")
            return False

        conn = GcpApiConsoleConnection(
            project_id=project_id,
            token=token,
            client_email=client_email,
            scopes=self._scopes(),
            timeout=int(self.timeout),
        )
        try:
            print_status(f"Testing GCP API console for project {project_id}...")
            output = conn.run_command(self._as_str(self.test_command) or "whoami")
            if output:
                print_info(output[:4000])
            print_success("GCP API console session ready")
            return (
                conn,
                f"gcp-api-{project_id}",
                0,
                {
                    "project_id": project_id,
                    "client_email": client_email,
                    "scopes": self._scopes(),
                    "session_type": "gcp_api",
                    "protocol": "gcp_api",
                },
            )
        except Exception as e:
            print_error(f"GCP API console failed: {e}")
            return False
