#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Kubernetes session helpers for post-exploitation modules."""

from __future__ import annotations

from typing import Any, Dict, Optional

from lib.protocols.kubernetes.kubernetes_client import KubernetesApiConnection, KubernetesClient


class KubernetesSessionMixin:
    """Resolve live KubernetesClient instances from framework session registries."""

    def _opt_value(self, name: str):
        attr = getattr(self, name, None)
        if attr is None:
            return None
        return attr.value if hasattr(attr, "value") else attr

    def _resolve_session(self):
        if hasattr(self, "session") and self.session:
            return self.session
        session_id = self._opt_value("session_id")
        framework = getattr(self, "framework", None)
        if session_id and framework and hasattr(framework, "session_manager"):
            return framework.session_manager.get_session(str(session_id))
        return None

    def _session_id(self, session) -> str:
        return str(getattr(session, "session_id", getattr(session, "id", "")) or "")

    def _session_data(self, session) -> Dict[str, Any]:
        data = getattr(session, "data", None)
        return data if isinstance(data, dict) else {}

    def _k8s_registry(self):
        framework = getattr(self, "framework", None)
        if not framework:
            return {}
        registry = getattr(framework, "_kubernetes_session_clients", None)
        if registry is None:
            framework._kubernetes_session_clients = {}
            registry = framework._kubernetes_session_clients
        return registry

    def _client_from_listener(self, session) -> Optional[KubernetesClient]:
        framework = getattr(self, "framework", None)
        if not framework:
            return None
        data = self._session_data(session)
        listener_id = data.get("listener_id")
        session_id = self._session_id(session)
        if not listener_id or not session_id:
            return None
        listener = getattr(framework, "active_listeners", {}).get(listener_id)
        if not listener or not hasattr(listener, "_session_connections"):
            return None
        conn = listener._session_connections.get(session_id)
        if isinstance(conn, KubernetesApiConnection):
            return conn.client
        if isinstance(conn, KubernetesClient):
            return conn
        return None

    def get_kubernetes_connection_info(self) -> Dict[str, Any]:
        session = self._resolve_session()
        if session:
            data = self._session_data(session)
            return {
                "api_server": data.get("api_server") or data.get("host") or getattr(session, "host", ""),
                "token": data.get("token") or "",
                "namespace": data.get("namespace") or "default",
                "insecure": bool(data.get("insecure", False)),
                "timeout": float(data.get("timeout") or 30),
                "ca_file": data.get("ca_file") or "",
                "certificate_authority_data": data.get("certificate_authority_data") or "",
                "kubeconfig": data.get("kubeconfig") or "",
                "context": data.get("context") or "",
            }
        return {
            "api_server": str(self._opt_value("api_server") or self._opt_value("rhost") or ""),
            "token": str(self._opt_value("token") or ""),
            "namespace": str(self._opt_value("namespace") or "default"),
            "insecure": bool(self._opt_value("insecure") or False),
            "timeout": float(self._opt_value("timeout") or 30),
            "ca_file": str(self._opt_value("ca_file") or ""),
            "certificate_authority_data": "",
            "kubeconfig": str(self._opt_value("kubeconfig") or ""),
            "context": str(self._opt_value("context") or ""),
        }

    def _build_kubernetes_client(self, info: Dict[str, Any]) -> KubernetesClient:
        kubeconfig = str(info.get("kubeconfig") or "").strip()
        if kubeconfig:
            return KubernetesClient.from_kubeconfig(
                path=kubeconfig,
                context=str(info.get("context") or ""),
                namespace=str(info.get("namespace") or "default"),
                insecure=bool(info.get("insecure")),
                timeout=float(info.get("timeout") or 30),
            )
        return KubernetesClient(
            api_server=str(info.get("api_server") or ""),
            token=str(info.get("token") or ""),
            certificate_authority_data=str(info.get("certificate_authority_data") or ""),
            ca_file=str(info.get("ca_file") or ""),
            insecure=bool(info.get("insecure")),
            namespace=str(info.get("namespace") or "default"),
            timeout=float(info.get("timeout") or 30),
        )

    def get_kubernetes_client(self) -> KubernetesClient:
        session = self._resolve_session()
        if session:
            session_id = self._session_id(session)
            registry_client = self._k8s_registry().get(session_id)
            if isinstance(registry_client, KubernetesClient) and registry_client.connected:
                return registry_client
            if isinstance(registry_client, KubernetesApiConnection) and registry_client.connected:
                return registry_client.client

            listener_client = self._client_from_listener(session)
            if listener_client and listener_client.connected:
                return listener_client

            info = self.get_kubernetes_connection_info()
            if info.get("api_server") or info.get("kubeconfig"):
                client = self._build_kubernetes_client(info)
                if client.connect():
                    self._k8s_registry()[session_id] = client
                    return client

        info = self.get_kubernetes_connection_info()
        if info.get("api_server") or info.get("kubeconfig"):
            client = self._build_kubernetes_client(info)
            if client.connect():
                return client

        raise RuntimeError("No Kubernetes session and no api_server/kubeconfig configured.")

    def open_kubernetes(self) -> KubernetesClient:
        return self.get_kubernetes_client()

    def k8s_namespace(self, override: str = "") -> str:
        if override:
            return str(override)
        opt = self._opt_value("namespace")
        if opt:
            return str(opt)
        return str(self.get_kubernetes_connection_info().get("namespace") or "default")

    def close_kubernetes_client(self, session_id: str) -> None:
        framework = getattr(self, "framework", None)
        if not framework:
            return
        registry = getattr(framework, "_kubernetes_session_clients", None) or {}
        client = registry.pop(session_id, None)
        if client and hasattr(client, "close"):
            try:
                client.close()
            except Exception:
                pass
