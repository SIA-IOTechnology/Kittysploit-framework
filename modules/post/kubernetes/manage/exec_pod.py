#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Kubernetes exec into a pod via the API websocket exec endpoint."""

from kittysploit import *
from lib.protocols.kubernetes.kubernetes_session_mixin import KubernetesSessionMixin
import shlex


class Module(Post, KubernetesSessionMixin):
    __info__ = {
        "name": "Kubernetes Exec Pod",
        "description": "Executes a command inside a running pod through the Kubernetes API",
        "author": "KittySploit Team",
        "version": "1.0.0",
        "session_type": SessionType.KUBERNETES,
        "tags": ["kubernetes", "k8s", "manage", "exec", "rce"],
        "references": [
            "https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.29/#-strong-exec-operations-pod-v1-core-strong-",
            "https://attack.mitre.org/techniques/T1609/",
        ],
        "agent": {
            "risk": "intrusive",
            "effects": ["active_exploitation"],
            "expected_requests": 2,
            "reversible": True,
            "approval_required": True,
            "produces": ["risk_signals"],
            "chain": {
                "consumes_capabilities": ["k8s_pods"],
                "produces_capabilities": [{"capability": "pod_shell", "from_detail": ""}],
                "suggested_followups": [
                    "post/kubernetes/pivot/port_forward",
                    "post/kubernetes/gather/secrets",
                ],
            },
        },
    }

    pod = OptString("", "Pod name", True)
    namespace = OptString("", "Namespace (empty = session default)", False)
    container = OptString("", "Container name (optional)", False)
    command = OptString("id", "Command to run (shell-quoted string)", True)
    shell = OptBool(
        False,
        "Wrap command as /bin/sh -c '<command>'",
        False,
    )
    dry_run = OptBool(False, "Validate options only — do not exec", False)

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
            self.open_kubernetes()
            return True
        except Exception as exc:
            print_error(str(exc))
            return False

    def run(self):
        client = self.open_kubernetes()
        pod = str(self.pod).strip()
        ns = self.k8s_namespace(str(self.namespace or ""))
        container = str(self.container or "").strip()
        raw_cmd = str(self.command or "").strip()
        if not raw_cmd:
            print_error("command is required")
            return False

        if bool(self.shell):
            argv = ["/bin/sh", "-c", raw_cmd]
        else:
            try:
                argv = shlex.split(raw_cmd)
            except ValueError as exc:
                print_error(f"Invalid command quoting: {exc}")
                return False

        print_info("=" * 80)
        print_success("Kubernetes Exec Pod")
        print_info(f"  pod       : {ns}/{pod}")
        print_info(f"  container : {container or '(default)'}")
        print_info(f"  argv      : {argv}")
        print_info("=" * 80)

        if bool(self.dry_run):
            print_success("Dry run — exec not sent")
            return True

        print_warning(f"Executing in {ns}/{pod}...")
        result = client.exec_command(pod, argv, namespace=ns, container=container)
        if result.stdout:
            print_info(result.stdout if result.stdout.endswith("\n") else result.stdout + "\n")
        if result.stderr:
            print_warning(result.stderr)
        if not result.success:
            print_error(result.error or "exec failed")
            return False

        if result.exit_code is not None:
            print_info(f"exit_code={result.exit_code}")
        print_success("Exec completed")

        session = self._resolve_session()
        if session:
            data = session.data if isinstance(session.data, dict) else {}
            data["last_exec"] = {
                "pod": pod,
                "namespace": ns,
                "container": container,
                "command": argv,
                "stdout": result.stdout,
                "stderr": result.stderr,
                "exit_code": result.exit_code,
            }
            session.data = data
        return True
