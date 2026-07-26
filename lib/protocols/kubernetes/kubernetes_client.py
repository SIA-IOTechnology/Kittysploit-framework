#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Kubernetes API client (REST + websocket exec/port-forward)."""

from __future__ import annotations

import base64
import json
import os
import socket
import ssl
import threading
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional
from urllib.parse import quote, urlencode, urlparse

import requests

try:
    import websocket
except ImportError:  # pragma: no cover
    websocket = None


@dataclass
class K8sResponse:
    ok: bool
    status_code: int
    body: Any = None
    url: str = ""
    error: str = ""


@dataclass
class K8sExecResult:
    success: bool
    stdout: str = ""
    stderr: str = ""
    error: str = ""
    exit_code: Optional[int] = None


class KubernetesClient:
    """Lightweight Kubernetes API client using requests (+ websocket-client)."""

    def __init__(
        self,
        api_server: str,
        token: str = "",
        certificate_authority_data: str = "",
        ca_file: str = "",
        insecure: bool = False,
        namespace: str = "default",
        timeout: float = 30.0,
        client_cert: str = "",
        client_key: str = "",
    ):
        self.api_server = str(api_server or "").rstrip("/")
        self.token = str(token or "").strip()
        self.certificate_authority_data = str(certificate_authority_data or "").strip()
        self.ca_file = str(ca_file or "").strip()
        self.insecure = bool(insecure)
        self.namespace = str(namespace or "default")
        self.timeout = float(timeout or 30)
        self.client_cert = str(client_cert or "").strip()
        self.client_key = str(client_key or "").strip()
        self._ca_temp: Optional[str] = None
        self._session = requests.Session()
        self._configure_tls()

    @property
    def connected(self) -> bool:
        return bool(self.api_server)

    def close(self) -> None:
        try:
            self._session.close()
        except Exception:
            pass
        if self._ca_temp and os.path.isfile(self._ca_temp):
            try:
                os.unlink(self._ca_temp)
            except OSError:
                pass
            self._ca_temp = None

    def _configure_tls(self) -> None:
        if self.insecure:
            self._session.verify = False
            try:
                import urllib3

                urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            except Exception:
                pass
            return
        if self.ca_file and os.path.isfile(self.ca_file):
            self._session.verify = self.ca_file
            return
        if self.certificate_authority_data:
            import tempfile

            raw = self.certificate_authority_data
            try:
                pem = base64.b64decode(raw)
            except Exception:
                pem = raw.encode("utf-8") if isinstance(raw, str) else raw
            fd, path = tempfile.mkstemp(prefix="k8s-ca-", suffix=".crt")
            os.close(fd)
            with open(path, "wb") as handle:
                handle.write(pem if isinstance(pem, bytes) else pem.encode("utf-8"))
            self._ca_temp = path
            self._session.verify = path
            return
        self._session.verify = True

    def _headers(self, content_type: str = "application/json") -> Dict[str, str]:
        headers = {"Accept": "application/json"}
        if content_type:
            headers["Content-Type"] = content_type
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        return headers

    def _cert(self):
        if self.client_cert and self.client_key:
            return (self.client_cert, self.client_key)
        return None

    def request(
        self,
        method: str,
        path: str,
        params: Optional[Dict] = None,
        json_body: Any = None,
        data: Any = None,
        content_type: str = "application/json",
    ) -> K8sResponse:
        if not self.api_server:
            return K8sResponse(ok=False, status_code=0, error="api_server not set")
        url = path if path.startswith("http") else f"{self.api_server}{path}"
        try:
            response = self._session.request(
                method.upper(),
                url,
                headers=self._headers(content_type),
                params=params,
                json=json_body,
                data=data,
                timeout=self.timeout,
                cert=self._cert(),
            )
            try:
                body = response.json()
            except Exception:
                body = response.text
            return K8sResponse(
                ok=response.ok,
                status_code=response.status_code,
                body=body,
                url=response.url,
                error="" if response.ok else self._extract_error(body, response.status_code),
            )
        except Exception as exc:
            return K8sResponse(ok=False, status_code=0, error=str(exc), url=url)

    @staticmethod
    def _extract_error(body: Any, status: int) -> str:
        if isinstance(body, dict):
            msg = body.get("message") or body.get("reason") or ""
            if msg:
                return f"{status}: {msg}"
        return f"HTTP {status}"

    def get(self, path: str, params: Optional[Dict] = None) -> K8sResponse:
        return self.request("GET", path, params=params)

    def post(self, path: str, json_body: Any = None, params: Optional[Dict] = None) -> K8sResponse:
        return self.request("POST", path, params=params, json_body=json_body)

    def connect(self) -> bool:
        """Smoke-test the API (/version)."""
        result = self.get("/version")
        return result.ok

    def get_version(self) -> Dict[str, Any]:
        result = self.get("/version")
        return result.body if result.ok and isinstance(result.body, dict) else {}

    def whoami(self) -> Dict[str, Any]:
        """Resolve caller identity via SelfSubjectReview when available."""
        info: Dict[str, Any] = {
            "api_server": self.api_server,
            "namespace": self.namespace,
            "auth": "token" if self.token else "anonymous/cert",
        }
        version = self.get_version()
        if version:
            info["version"] = {
                "gitVersion": version.get("gitVersion"),
                "platform": version.get("platform"),
                "major": version.get("major"),
                "minor": version.get("minor"),
            }

        # authentication.k8s.io/v1 SelfSubjectReview (1.28+)
        ssr = self.post(
            "/apis/authentication.k8s.io/v1/selfsubjectreviews",
            json_body={"apiVersion": "authentication.k8s.io/v1", "kind": "SelfSubjectReview"},
        )
        if ssr.ok and isinstance(ssr.body, dict):
            user = ((ssr.body.get("status") or {}).get("userInfo")) or {}
            info["username"] = user.get("username", "")
            info["uid"] = user.get("uid", "")
            info["groups"] = user.get("groups") or []
            info["extra"] = user.get("extra") or {}
        else:
            # Fallback: TokenReview is not self-serving without audience; use rules review presence
            info["username"] = "unknown"
            info["selfsubjectreview_error"] = ssr.error or f"HTTP {ssr.status_code}"

        rules = self.self_subject_rules(self.namespace)
        info["rules_namespace"] = self.namespace
        info["rules"] = rules.get("resourceRules") or []
        info["non_resource_rules"] = rules.get("nonResourceRules") or []
        info["incomplete"] = bool(rules.get("incomplete"))
        return info

    def self_subject_rules(self, namespace: str = "") -> Dict[str, Any]:
        ns = namespace or self.namespace or ""
        body = {
            "apiVersion": "authorization.k8s.io/v1",
            "kind": "SelfSubjectRulesReview",
            "spec": {"namespace": ns},
        }
        result = self.post("/apis/authorization.k8s.io/v1/selfsubjectrulesreviews", json_body=body)
        if not result.ok or not isinstance(result.body, dict):
            return {"error": result.error or f"HTTP {result.status_code}"}
        return result.body.get("status") or {}

    def can_i(self, verb: str, resource: str, namespace: str = "", name: str = "", group: str = "") -> bool:
        body = {
            "apiVersion": "authorization.k8s.io/v1",
            "kind": "SelfSubjectAccessReview",
            "spec": {
                "resourceAttributes": {
                    "namespace": namespace or self.namespace,
                    "verb": verb,
                    "resource": resource,
                    "name": name,
                    "group": group,
                }
            },
        }
        result = self.post("/apis/authorization.k8s.io/v1/selfsubjectaccessreviews", json_body=body)
        if not result.ok or not isinstance(result.body, dict):
            return False
        return bool((result.body.get("status") or {}).get("allowed"))

    def list_namespaces(self) -> K8sResponse:
        return self.get("/api/v1/namespaces")

    def list_pods(self, namespace: Optional[str] = None, all_namespaces: bool = False, label_selector: str = "") -> K8sResponse:
        params = {}
        if label_selector:
            params["labelSelector"] = label_selector
        if all_namespaces:
            return self.get("/api/v1/pods", params=params or None)
        ns = namespace or self.namespace
        return self.get(f"/api/v1/namespaces/{quote(ns, safe='')}/pods", params=params or None)

    def list_secrets(
        self,
        namespace: Optional[str] = None,
        all_namespaces: bool = False,
        label_selector: str = "",
    ) -> K8sResponse:
        params = {}
        if label_selector:
            params["labelSelector"] = label_selector
        if all_namespaces:
            return self.get("/api/v1/secrets", params=params or None)
        ns = namespace or self.namespace
        return self.get(f"/api/v1/namespaces/{quote(ns, safe='')}/secrets", params=params or None)

    def get_secret(self, name: str, namespace: Optional[str] = None) -> K8sResponse:
        ns = namespace or self.namespace
        return self.get(f"/api/v1/namespaces/{quote(ns, safe='')}/secrets/{quote(name, safe='')}")

    def list_roles(self, namespace: Optional[str] = None) -> K8sResponse:
        ns = namespace or self.namespace
        return self.get(f"/apis/rbac.authorization.k8s.io/v1/namespaces/{quote(ns, safe='')}/roles")

    def list_role_bindings(self, namespace: Optional[str] = None) -> K8sResponse:
        ns = namespace or self.namespace
        return self.get(f"/apis/rbac.authorization.k8s.io/v1/namespaces/{quote(ns, safe='')}/rolebindings")

    def list_cluster_roles(self) -> K8sResponse:
        return self.get("/apis/rbac.authorization.k8s.io/v1/clusterroles")

    def list_cluster_role_bindings(self) -> K8sResponse:
        return self.get("/apis/rbac.authorization.k8s.io/v1/clusterrolebindings")

    @staticmethod
    def decode_secret_data(data: Dict[str, str]) -> Dict[str, str]:
        out = {}
        for key, value in (data or {}).items():
            try:
                out[key] = base64.b64decode(value).decode("utf-8", errors="replace")
            except Exception:
                out[key] = value
        return out

    def exec_command(
        self,
        pod: str,
        command: List[str],
        namespace: Optional[str] = None,
        container: str = "",
        timeout: Optional[float] = None,
    ) -> K8sExecResult:
        """Execute a command in a pod via the Kubernetes websocket exec API."""
        if websocket is None:
            return K8sExecResult(success=False, error="websocket-client is required for pod exec")
        if not command:
            return K8sExecResult(success=False, error="empty command")

        ns = namespace or self.namespace
        params = [("stdout", "true"), ("stderr", "true"), ("stdin", "false"), ("tty", "false")]
        for part in command:
            params.append(("command", part))
        if container:
            params.append(("container", container))

        path = f"/api/v1/namespaces/{quote(ns, safe='')}/pods/{quote(pod, safe='')}/exec?{urlencode(params)}"
        ws_url = self._ws_url(path)
        headers = []
        if self.token:
            headers.append(f"Authorization: Bearer {self.token}")

        stdout_chunks: List[bytes] = []
        stderr_chunks: List[bytes] = []
        error_chunks: List[bytes] = []
        wait = float(timeout if timeout is not None else self.timeout)

        sslopt = self._ws_sslopt()
        try:
            ws = websocket.create_connection(
                ws_url,
                header=headers,
                sslopt=sslopt,
                timeout=wait,
                subprotocols=["v4.channel.k8s.io", "v3.channel.k8s.io", "v2.channel.k8s.io"],
            )
        except Exception as exc:
            return K8sExecResult(success=False, error=f"websocket connect failed: {exc}")

        deadline = time.time() + wait
        try:
            while time.time() < deadline:
                try:
                    ws.settimeout(max(0.1, deadline - time.time()))
                    message = ws.recv()
                except Exception:
                    break
                if message is None:
                    break
                if isinstance(message, str):
                    message = message.encode("utf-8", errors="replace")
                if not message:
                    continue
                channel = message[0]
                payload = message[1:]
                if channel == 1:
                    stdout_chunks.append(payload)
                elif channel == 2:
                    stderr_chunks.append(payload)
                elif channel == 3:
                    error_chunks.append(payload)
        finally:
            try:
                ws.close()
            except Exception:
                pass

        stdout = b"".join(stdout_chunks).decode("utf-8", errors="replace")
        stderr = b"".join(stderr_chunks).decode("utf-8", errors="replace")
        err_text = b"".join(error_chunks).decode("utf-8", errors="replace")
        exit_code = None
        if err_text:
            try:
                meta = json.loads(err_text)
                if isinstance(meta, dict) and meta.get("status") == "Success":
                    exit_code = 0
                elif isinstance(meta, dict):
                    details = meta.get("details") or {}
                    causes = details.get("causes") or []
                    for cause in causes:
                        if cause.get("reason") == "ExitCode":
                            exit_code = int(cause.get("message") or 1)
            except Exception:
                pass
        success = exit_code == 0 or (exit_code is None and not err_text.startswith("Failure"))
        if err_text and '"status":"Failure"' in err_text.replace(" ", ""):
            success = False
        return K8sExecResult(
            success=success or bool(stdout),
            stdout=stdout,
            stderr=stderr,
            error=err_text if not success else "",
            exit_code=exit_code,
        )

    def port_forward(
        self,
        pod: str,
        local_port: int,
        remote_port: int,
        namespace: Optional[str] = None,
        bind: str = "127.0.0.1",
        stop_event: Optional[threading.Event] = None,
    ) -> threading.Thread:
        """
        Start a local TCP listener that forwards to pod:remote_port via K8s portforward API.
        Returns the server thread (daemon). Set stop_event to stop.
        """
        if websocket is None:
            raise RuntimeError("websocket-client is required for port-forward")

        ns = namespace or self.namespace
        stop_event = stop_event or threading.Event()

        def _serve():
            server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server.bind((bind, int(local_port)))
            server.listen(5)
            server.settimeout(1.0)
            try:
                while not stop_event.is_set():
                    try:
                        client, _addr = server.accept()
                    except socket.timeout:
                        continue
                    except OSError:
                        break
                    t = threading.Thread(
                        target=self._handle_portforward_client,
                        args=(client, pod, ns, int(remote_port)),
                        daemon=True,
                    )
                    t.start()
            finally:
                try:
                    server.close()
                except Exception:
                    pass

        thread = threading.Thread(target=_serve, daemon=True)
        thread.start()
        return thread

    def _handle_portforward_client(self, client: socket.socket, pod: str, ns: str, remote_port: int) -> None:
        path = (
            f"/api/v1/namespaces/{quote(ns, safe='')}/pods/{quote(pod, safe='')}"
            f"/portforward?ports={int(remote_port)}"
        )
        ws_url = self._ws_url(path)
        headers = []
        if self.token:
            headers.append(f"Authorization: Bearer {self.token}")
        try:
            ws = websocket.create_connection(
                ws_url,
                header=headers,
                sslopt=self._ws_sslopt(),
                timeout=self.timeout,
                subprotocols=["v4.channel.k8s.io", "v2.channel.k8s.io"],
            )
        except Exception:
            try:
                client.close()
            except Exception:
                pass
            return

        # Portforward protocol: first messages may include port ack on channels 0/1
        client.settimeout(0.5)
        stop = threading.Event()

        def _tcp_to_ws():
            try:
                while not stop.is_set():
                    try:
                        data = client.recv(4096)
                    except socket.timeout:
                        continue
                    except OSError:
                        break
                    if not data:
                        break
                    # channel 0 = data
                    ws.send(b"\x00" + data, opcode=websocket.ABNF.OPCODE_BINARY)
            finally:
                stop.set()

        def _ws_to_tcp():
            try:
                while not stop.is_set():
                    try:
                        ws.settimeout(0.5)
                        message = ws.recv()
                    except Exception:
                        continue
                    if message is None:
                        break
                    if isinstance(message, str):
                        message = message.encode("utf-8", errors="replace")
                    if len(message) < 1:
                        continue
                    channel = message[0]
                    payload = message[1:]
                    if channel == 0 and payload:
                        # skip 2-byte port header frames sometimes sent first
                        if len(payload) == 2:
                            continue
                        try:
                            client.sendall(payload)
                        except OSError:
                            break
            finally:
                stop.set()

        t1 = threading.Thread(target=_tcp_to_ws, daemon=True)
        t2 = threading.Thread(target=_ws_to_tcp, daemon=True)
        t1.start()
        t2.start()
        t1.join()
        t2.join()
        try:
            ws.close()
        except Exception:
            pass
        try:
            client.close()
        except Exception:
            pass

    def _ws_url(self, path: str) -> str:
        parsed = urlparse(self.api_server)
        scheme = "wss" if parsed.scheme == "https" else "ws"
        return f"{scheme}://{parsed.netloc}{path}"

    def _ws_sslopt(self) -> Dict[str, Any]:
        if self.insecure:
            return {"cert_reqs": ssl.CERT_NONE, "check_hostname": False}
        opts: Dict[str, Any] = {}
        verify = self._session.verify
        if isinstance(verify, str) and os.path.isfile(verify):
            opts["ca_certs"] = verify
            opts["cert_reqs"] = ssl.CERT_REQUIRED
        return opts

    # --- kubeconfig helpers ---

    @classmethod
    def from_kubeconfig(
        cls,
        path: str = "",
        context: str = "",
        namespace: str = "",
        insecure: bool = False,
        timeout: float = 30.0,
    ) -> "KubernetesClient":
        path = path or os.path.expanduser(os.environ.get("KUBECONFIG", "~/.kube/config"))
        path = os.path.expanduser(path)
        if not os.path.isfile(path):
            raise FileNotFoundError(f"kubeconfig not found: {path}")
        cfg = cls._load_kubeconfig(path)
        current = context or cfg.get("current-context") or ""
        contexts = {c.get("name"): c.get("context") or {} for c in cfg.get("contexts") or []}
        clusters = {c.get("name"): c.get("cluster") or {} for c in cfg.get("clusters") or []}
        users = {u.get("name"): u.get("user") or {} for u in cfg.get("users") or []}
        ctx = contexts.get(current) or {}
        cluster = clusters.get(ctx.get("cluster", "")) or {}
        user = users.get(ctx.get("user", "")) or {}
        api_server = cluster.get("server") or ""
        ns = namespace or ctx.get("namespace") or "default"
        token = user.get("token") or ""
        if not token and user.get("tokenFile"):
            with open(os.path.expanduser(user["tokenFile"]), "r", encoding="utf-8") as handle:
                token = handle.read().strip()
        # exec auth is out of scope — require token/client-cert
        ca_data = cluster.get("certificate-authority-data") or ""
        ca_file = cluster.get("certificate-authority") or ""
        if ca_file:
            ca_file = os.path.expanduser(ca_file)
        client_cert = user.get("client-certificate") or ""
        client_key = user.get("client-key") or ""
        if user.get("client-certificate-data") and not client_cert:
            client_cert = cls._write_temp_b64(user["client-certificate-data"], ".crt")
        if user.get("client-key-data") and not client_key:
            client_key = cls._write_temp_b64(user["client-key-data"], ".key")
        skip_tls = bool(cluster.get("insecure-skip-tls-verify")) or insecure
        return cls(
            api_server=api_server,
            token=token,
            certificate_authority_data=ca_data,
            ca_file=ca_file,
            insecure=skip_tls,
            namespace=ns,
            timeout=timeout,
            client_cert=os.path.expanduser(client_cert) if client_cert else "",
            client_key=os.path.expanduser(client_key) if client_key else "",
        )

    @staticmethod
    def _write_temp_b64(data: str, suffix: str) -> str:
        import tempfile

        raw = base64.b64decode(data)
        fd, path = tempfile.mkstemp(prefix="k8s-cred-", suffix=suffix)
        os.close(fd)
        with open(path, "wb") as handle:
            handle.write(raw)
        return path

    @staticmethod
    def _load_kubeconfig(path: str) -> Dict[str, Any]:
        with open(path, "r", encoding="utf-8") as handle:
            text = handle.read()
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            pass
        try:
            import yaml
        except ImportError as exc:
            raise RuntimeError(
                "kubeconfig is YAML but PyYAML is not installed; "
                "use token/api_server options or pip install pyyaml"
            ) from exc
        data = yaml.safe_load(text)
        if not isinstance(data, dict):
            raise ValueError("invalid kubeconfig")
        return data


class KubernetesApiConnection:
    """Interactive connection wrapper stored on the listener session."""

    def __init__(self, client: KubernetesClient):
        self.client = client

    @property
    def connected(self) -> bool:
        return self.client.connected

    def close(self) -> None:
        self.client.close()

    def help_text(self) -> str:
        return "\n".join(
            [
                "Kubernetes API commands:",
                "  help                         Show this help",
                "  whoami                       Show identity + rules summary",
                "  version                      Cluster /version",
                "  ns | namespaces              List namespaces",
                "  pods [namespace|-A]          List pods",
                "  secrets [namespace|-A]       List secrets (metadata)",
                "  can-i <verb> <resource>      SelfSubjectAccessReview",
                "  get <path>                   Raw GET against API path",
                "  exec <pod> -- <cmd...>       Exec in pod (current ns)",
            ]
        )

    def run_command(self, command: str) -> str:
        command = (command or "").strip()
        if not command:
            return ""
        parts = command.split()
        cmd = parts[0].lower()
        args = parts[1:]
        c = self.client

        if cmd in ("help", "?"):
            return self.help_text()
        if cmd == "whoami":
            return json.dumps(c.whoami(), indent=2, ensure_ascii=False)
        if cmd == "version":
            return json.dumps(c.get_version(), indent=2, ensure_ascii=False)
        if cmd in ("ns", "namespaces"):
            return self._fmt(c.list_namespaces())
        if cmd == "pods":
            all_ns = "-A" in args or "--all-namespaces" in args
            ns = ""
            for a in args:
                if not a.startswith("-"):
                    ns = a
                    break
            return self._fmt(c.list_pods(namespace=ns or None, all_namespaces=all_ns))
        if cmd == "secrets":
            all_ns = "-A" in args or "--all-namespaces" in args
            ns = ""
            for a in args:
                if not a.startswith("-"):
                    ns = a
                    break
            return self._fmt(c.list_secrets(namespace=ns or None, all_namespaces=all_ns))
        if cmd == "can-i":
            if len(args) < 2:
                return "Usage: can-i <verb> <resource> [namespace]"
            ns = args[2] if len(args) > 2 else c.namespace
            allowed = c.can_i(args[0], args[1], namespace=ns)
            return json.dumps({"allowed": allowed, "verb": args[0], "resource": args[1], "namespace": ns}, indent=2)
        if cmd == "get":
            if not args:
                return "Usage: get <api-path>"
            return self._fmt(c.get(args[0]))
        if cmd == "exec":
            if "--" in parts:
                idx = parts.index("--")
                pod = parts[1] if idx > 1 else ""
                argv = parts[idx + 1 :]
            else:
                if len(parts) < 3:
                    return "Usage: exec <pod> -- <command...>"
                pod = parts[1]
                argv = parts[2:]
            if not pod or not argv:
                return "Usage: exec <pod> -- <command...>"
            result = c.exec_command(pod, argv)
            out = result.stdout
            if result.stderr:
                out = (out + ("\n" if out else "") + result.stderr).strip()
            if result.error and not result.success:
                return f"exec failed: {result.error}\n{out}"
            return out or "(no output)"
        return f"Unknown command: {cmd}\n\n{self.help_text()}"

    @staticmethod
    def _fmt(result: K8sResponse) -> str:
        body = result.body
        if isinstance(body, (dict, list)):
            rendered = json.dumps(body, indent=2, ensure_ascii=False)
        else:
            rendered = str(body or "")
        return f"HTTP {result.status_code} {result.url}\n{rendered}"
