#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Kubernetes port-forward — local TCP listener to a pod port via the API."""

from kittysploit import *
from lib.protocols.kubernetes.kubernetes_session_mixin import KubernetesSessionMixin
import socket
import threading
import time


class Module(Post, KubernetesSessionMixin):
    __info__ = {
        "name": "Kubernetes Port Forward",
        "description": (
            "Forwards a local TCP port to a pod port through the Kubernetes "
            "portforward API (pivot into cluster services)"
        ),
        "author": "KittySploit Team",
        "version": "1.0.0",
        "session_type": SessionType.KUBERNETES,
        "tags": ["kubernetes", "k8s", "pivot", "portforward", "tunnel"],
        "references": [
            "https://kubernetes.io/docs/tasks/access-application-cluster/port-forward-access-application-cluster/",
            "https://attack.mitre.org/techniques/T1572/",
        ],
        "agent": {
            "risk": "intrusive",
            "effects": ["network_pivot", "active_exploitation"],
            "expected_requests": 2,
            "reversible": True,
            "approval_required": True,
            "produces": ["network_access"],
            "chain": {
                "consumes_capabilities": ["k8s_pods"],
                "produces_capabilities": [{"capability": "k8s_portforward", "from_detail": ""}],
                "suggested_followups": [
                    "post/kubernetes/manage/exec_pod",
                ],
            },
        },
    }

    pod = OptString("", "Pod name", True)
    namespace = OptString("", "Namespace (empty = session default)", False)
    local_port = OptPort(18080, "Local listen port", True)
    remote_port = OptPort(80, "Remote pod port", True)
    bind = OptString("127.0.0.1", "Local bind address", False)
    duration = OptInteger(
        60,
        "Seconds to keep the forwarder alive (0 = until interrupted / background listener)",
        False,
    )
    dry_run = OptBool(False, "Validate only — do not open the tunnel", False)

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
        if not str(self.pod or "").strip():
            print_error("pod is required")
            return False
        try:
            import websocket  # noqa: F401
        except ImportError:
            print_error("websocket-client is required for port-forward")
            print_info("Install it with: pip install websocket-client")
            return False
        try:
            self.open_kubernetes()
            return True
        except Exception as exc:
            print_error(str(exc))
            return False

    def run(self):
        client = self.open_kubernetes()
        pod = str(self.pod).strip()
        ns = self.k8s_namespace(str(self.namespace or ""))
        local_port = int(self.local_port)
        remote_port = int(self.remote_port)
        bind = str(self.bind or "127.0.0.1").strip()
        duration = max(0, int(self.duration or 0))

        print_info("=" * 80)
        print_success("Kubernetes Port Forward")
        print_info(f"  pod         : {ns}/{pod}")
        print_info(f"  local       : {bind}:{local_port}")
        print_info(f"  remote      : :{remote_port}")
        print_info(f"  duration    : {duration or 'until stopped'}s")
        print_info("=" * 80)

        if bool(self.dry_run):
            print_success("Dry run — tunnel not opened")
            return True

        # Ensure local port is free
        probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            probe.bind((bind, local_port))
        except OSError as exc:
            print_error(f"Cannot bind {bind}:{local_port}: {exc}")
            return False
        finally:
            probe.close()

        stop_event = threading.Event()
        print_warning(f"Starting port-forward {bind}:{local_port} -> {ns}/{pod}:{remote_port}")
        try:
            thread = client.port_forward(
                pod=pod,
                local_port=local_port,
                remote_port=remote_port,
                namespace=ns,
                bind=bind,
                stop_event=stop_event,
            )
        except Exception as exc:
            print_error(f"Failed to start port-forward: {exc}")
            return False

        session = self._resolve_session()
        if session:
            data = session.data if isinstance(session.data, dict) else {}
            data["port_forward"] = {
                "pod": pod,
                "namespace": ns,
                "local": f"{bind}:{local_port}",
                "remote_port": remote_port,
            }
            session.data = data

        print_success(f"Listening on {bind}:{local_port} (forwarding to pod port {remote_port})")
        print_info("Use Ctrl+C to stop early" if duration else "Forwarder running in background thread")

        try:
            if duration > 0:
                end = time.time() + duration
                while time.time() < end and thread.is_alive():
                    time.sleep(0.5)
                stop_event.set()
                thread.join(timeout=3)
                print_success("Port-forward stopped")
            else:
                # Keep module "running" briefly so the thread is established, then leave it daemonized
                time.sleep(1)
                print_info("Daemon forwarder left running (session alive required)")
        except KeyboardInterrupt:
            stop_event.set()
            print_info("Interrupted — stopping forwarder")
            thread.join(timeout=3)

        return True
