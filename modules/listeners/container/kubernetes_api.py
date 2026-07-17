#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Kubernetes API bind listener — opens a cluster API session for post modules."""

from kittysploit import *
from lib.protocols.kubernetes.kubernetes_client import KubernetesApiConnection, KubernetesClient
import os


class Module(Listener):
    __info__ = {
        "name": "Kubernetes API",
        "description": (
            "Authenticates to a Kubernetes API server (token, kubeconfig, or "
            "in-cluster SA) and creates an interactive Kubernetes session"
        ),
        "author": "KittySploit Team",
        "version": "1.0.0",
        "handler": Handler.BIND,
        "session_type": SessionType.KUBERNETES,
        "protocol": "kubernetes",
        "references": [
            "https://kubernetes.io/docs/reference/kubernetes-api/",
            "https://attack.mitre.org/techniques/T1552/007/",
        ],
    }

    api_server = OptString(
        "",
        "Kubernetes API URL (e.g. https://127.0.0.1:6443). Empty with kubeconfig/in_cluster",
        False,
    )
    token = OptString("", "Bearer service account / user token", False)
    token_file = OptString("", "Path to token file", False)
    kubeconfig = OptString("", "Path to kubeconfig (default: $KUBECONFIG or ~/.kube/config)", False)
    context = OptString("", "kubeconfig context name", False)
    namespace = OptString("default", "Default namespace", False)
    ca_file = OptString("", "Path to cluster CA certificate", False)
    insecure = OptBool(False, "Skip TLS certificate verification", False)
    in_cluster = OptBool(
        False,
        "Use in-cluster service account (/var/run/secrets/kubernetes.io/serviceaccount)",
        False,
    )
    test_command = OptString("whoami", "Smoke-test command after connect", False)

    def run(self):
        try:
            client = self._build_client()
        except Exception as exc:
            print_error(str(exc))
            return False

        print_status(f"Connecting to Kubernetes API {client.api_server}...")
        if not client.connect():
            print_error("Kubernetes API connection failed (/version unreachable or unauthorized)")
            client.close()
            return False

        version = client.get_version()
        print_success(f"Kubernetes API session ready ({version.get('gitVersion') or 'unknown'})")
        print_info(f"  Server    : {client.api_server}")
        print_info(f"  Namespace : {client.namespace}")

        conn = KubernetesApiConnection(client)
        test_cmd = str(self.test_command or "whoami").strip()
        if test_cmd:
            try:
                output = conn.run_command(test_cmd)
                if output:
                    print_info(output[:3000])
            except Exception as exc:
                print_warning(f"Test command failed: {exc}")

        host = urlparse_host(client.api_server)
        port = urlparse_port(client.api_server)
        additional_data = {
            "api_server": client.api_server,
            "namespace": client.namespace,
            "insecure": client.insecure,
            "timeout": client.timeout,
            "ca_file": client.ca_file,
            "certificate_authority_data": client.certificate_authority_data,
            "kubeconfig": str(self.kubeconfig or ""),
            "context": str(self.context or ""),
            "auth_mode": self._auth_mode(),
            "git_version": version.get("gitVersion", ""),
            "protocol": "kubernetes",
            "session_type": "kubernetes",
            "platform": "cloud",
            # Do not persist raw token into session JSON if avoidable; keep for reconnect
            "token": client.token,
        }
        return (conn, host, port, additional_data)

    def shutdown(self):
        return True

    def _auth_mode(self) -> str:
        if bool(self.in_cluster):
            return "in_cluster"
        if str(self.kubeconfig or "").strip() or (
            not str(self.api_server or "").strip() and not str(self.token or "").strip()
        ):
            if str(self.kubeconfig or "").strip() or os.path.isfile(os.path.expanduser("~/.kube/config")):
                return "kubeconfig"
        if str(self.token or "").strip() or str(self.token_file or "").strip():
            return "token"
        return "unknown"

    def _build_client(self) -> KubernetesClient:
        timeout = float(self.timeout or 30)
        namespace = str(self.namespace or "default")
        insecure = bool(self.insecure)

        if bool(self.in_cluster):
            return self._from_in_cluster(namespace, insecure, timeout)

        kubeconfig = str(self.kubeconfig or "").strip()
        if kubeconfig or (
            not str(self.api_server or "").strip()
            and not str(self.token or "").strip()
            and not str(self.token_file or "").strip()
        ):
            path = kubeconfig or os.environ.get("KUBECONFIG") or "~/.kube/config"
            return KubernetesClient.from_kubeconfig(
                path=path,
                context=str(self.context or ""),
                namespace=namespace,
                insecure=insecure,
                timeout=timeout,
            )

        token = str(self.token or "").strip()
        token_file = str(self.token_file or "").strip()
        if not token and token_file:
            with open(os.path.expanduser(token_file), "r", encoding="utf-8") as handle:
                token = handle.read().strip()

        api_server = str(self.api_server or "").strip()
        if not api_server:
            raise RuntimeError("api_server is required when not using kubeconfig/in_cluster")
        if not api_server.startswith("http"):
            api_server = "https://" + api_server

        return KubernetesClient(
            api_server=api_server,
            token=token,
            ca_file=str(self.ca_file or "").strip(),
            insecure=insecure,
            namespace=namespace,
            timeout=timeout,
        )

    def _from_in_cluster(self, namespace: str, insecure: bool, timeout: float) -> KubernetesClient:
        root = "/var/run/secrets/kubernetes.io/serviceaccount"
        token_path = os.path.join(root, "token")
        ca_path = os.path.join(root, "ca.crt")
        ns_path = os.path.join(root, "namespace")
        if not os.path.isfile(token_path):
            raise RuntimeError(f"in-cluster token not found at {token_path}")
        with open(token_path, "r", encoding="utf-8") as handle:
            token = handle.read().strip()
        host = os.environ.get("KUBERNETES_SERVICE_HOST", "kubernetes.default.svc")
        port = os.environ.get("KUBERNETES_SERVICE_PORT", "443")
        api_server = f"https://{host}:{port}"
        ns = namespace
        if os.path.isfile(ns_path) and namespace == "default":
            with open(ns_path, "r", encoding="utf-8") as handle:
                ns = handle.read().strip() or namespace
        return KubernetesClient(
            api_server=api_server,
            token=token,
            ca_file=ca_path if os.path.isfile(ca_path) else "",
            insecure=insecure,
            namespace=ns,
            timeout=timeout,
        )


def urlparse_host(api_server: str) -> str:
    from urllib.parse import urlparse

    parsed = urlparse(api_server)
    return parsed.hostname or api_server


def urlparse_port(api_server: str) -> int:
    from urllib.parse import urlparse

    parsed = urlparse(api_server)
    if parsed.port:
        return int(parsed.port)
    return 443 if parsed.scheme == "https" else 80
