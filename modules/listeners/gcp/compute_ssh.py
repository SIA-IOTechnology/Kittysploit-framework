#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import os
import shutil
import subprocess
import tempfile

from kittysploit import *

_DEFAULT_SERVICE_ACCOUNT_FILES = ("service-account.json", "credentials.json", "gcp-service-account.json")


class GcpComputeSshConnection:
    def __init__(
        self,
        project_id,
        zone,
        instance_name,
        ssh_username,
        account,
        configuration,
        impersonate_service_account,
        access_token_file,
        owns_access_token_file,
        private_key_file,
        owns_private_key_file,
        use_iap,
        internal_ip,
        ssh_flags,
        timeout,
    ):
        self.project_id = project_id
        self.zone = zone
        self.instance_name = instance_name
        self.ssh_username = ssh_username
        self.account = account
        self.configuration = configuration
        self.impersonate_service_account = impersonate_service_account
        self.access_token_file = access_token_file
        self.owns_access_token_file = owns_access_token_file
        self.private_key_file = private_key_file
        self.owns_private_key_file = owns_private_key_file
        self.use_iap = use_iap
        self.internal_ip = internal_ip
        self.ssh_flags = ssh_flags
        self.timeout = int(timeout or 120)

    def _base_command(self):
        cmd = ["gcloud"]
        if self.access_token_file:
            cmd.extend(["--access-token-file", self.access_token_file])
        if self.configuration:
            cmd.extend(["--configuration", self.configuration])
        if self.account:
            cmd.extend(["--account", self.account])
        if self.impersonate_service_account:
            cmd.extend(["--impersonate-service-account", self.impersonate_service_account])
        target = self.instance_name
        if self.ssh_username:
            target = f"{self.ssh_username}@{self.instance_name}"
        cmd.extend([
            "compute",
            "ssh",
            target,
            "--project",
            self.project_id,
            "--zone",
            self.zone,
            "--quiet",
        ])
        if self.use_iap:
            cmd.append("--tunnel-through-iap")
        if self.internal_ip:
            cmd.append("--internal-ip")
        if self.private_key_file:
            cmd.extend(["--ssh-key-file", self.private_key_file])
        for flag in self.ssh_flags:
            cmd.extend(["--ssh-flag", flag])
        return cmd

    def run_command(self, command: str) -> str:
        cmd = self._base_command()
        cmd.extend(["--command", command])
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=self.timeout,
            check=False,
        )
        output = "\n".join(part for part in (result.stdout, result.stderr) if part)
        if result.returncode != 0:
            raise RuntimeError(output.strip() or f"gcloud exited with status {result.returncode}")
        return output.strip()

    def close(self):
        if self.owns_access_token_file and self.access_token_file:
            try:
                os.unlink(self.access_token_file)
            except OSError:
                pass
        if self.owns_private_key_file and self.private_key_file:
            try:
                os.unlink(self.private_key_file)
            except OSError:
                pass


class GcpParamikoSshConnection:
    def __init__(self, host, port, username, private_key_file, owns_private_key_file, timeout):
        self.host = host
        self.port = int(port or 22)
        self.username = username
        self.private_key_file = private_key_file
        self.owns_private_key_file = owns_private_key_file
        self.timeout = int(timeout or 120)
        self.client = None

    def _connect(self):
        if self.client:
            return self.client
        try:
            import paramiko
        except ImportError:
            raise RuntimeError("paramiko is required for backend=python")
        if not self.username:
            raise RuntimeError("ssh_username is required for backend=python")
        if not self.private_key_file:
            raise RuntimeError("private_key_file or private_key is required for backend=python")

        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        key_error = None
        pkey = None
        for key_cls in (
            paramiko.RSAKey,
            paramiko.ECDSAKey,
            paramiko.Ed25519Key,
            paramiko.DSSKey,
        ):
            try:
                pkey = key_cls.from_private_key_file(self.private_key_file)
                break
            except Exception as exc:
                key_error = exc
        if not pkey:
            raise RuntimeError(f"Could not load private SSH key: {key_error}")

        client.connect(
            hostname=self.host,
            port=self.port,
            username=self.username,
            pkey=pkey,
            timeout=self.timeout,
            banner_timeout=self.timeout,
            auth_timeout=self.timeout,
            look_for_keys=False,
            allow_agent=False,
        )
        self.client = client
        return client

    def run_command(self, command: str) -> str:
        client = self._connect()
        stdin, stdout, stderr = client.exec_command(command, timeout=self.timeout)
        out = stdout.read().decode("utf-8", errors="replace")
        err = stderr.read().decode("utf-8", errors="replace")
        status = stdout.channel.recv_exit_status()
        output = "\n".join(part for part in (out, err) if part)
        if status != 0:
            raise RuntimeError(output.strip() or f"ssh exited with status {status}")
        return output.strip()

    def close(self):
        if self.client:
            self.client.close()
            self.client = None
        if self.owns_private_key_file and self.private_key_file:
            try:
                os.unlink(self.private_key_file)
            except OSError:
                pass


class Module(Listener):
    __info__ = {
        "name": "Google Cloud Compute SSH Listener",
        "description": "Creates a command session to a Google Compute Engine VM via gcloud or direct SSH.",
        "author": "KittySploit Team",
        "version": "1.0.0",
        "handler": Handler.BIND,
        "session_type": "gcp_compute_ssh",
        "protocol": "gcp_compute_ssh",
        "dependencies": [],
        "optional_dependencies": ["google-auth", "paramiko"],
    }

    backend = OptChoice("auto", "Connection backend", False, choices=["auto", "python", "gcloud"])
    project_id = OptString("", "Google Cloud project ID", True)
    zone = OptString("", "Compute Engine zone, for example europe-west1-b", True)
    instance_name = OptString("", "Compute Engine instance name", True)
    ssh_username = OptString("", "SSH username; uses user@instance when set", False)
    account = OptString("", "gcloud account to use", False)
    configuration = OptString("", "gcloud named configuration to use", False, advanced=True)
    impersonate_service_account = OptString("", "Service account to impersonate", False, advanced=True)
    access_token_file = OptString("", "File containing an OAuth2 access token for gcloud", False, advanced=True)
    access_token = OptString("", "Raw OAuth2 access token; stored in a temporary 0600 file", False, advanced=True)
    service_account_file = OptString(
        "",
        "Service account JSON key file (also auto-detected from GOOGLE_APPLICATION_CREDENTIALS or service-account.json)",
        False,
    )
    service_account_json = OptString("", "Raw Google service account JSON key used to mint an access token", False, advanced=True)
    auth_scopes = OptString("https://www.googleapis.com/auth/cloud-platform", "Comma-separated OAuth scopes for service account auth", False, advanced=True)
    private_key_file = OptString("", "Private SSH key file passed to gcloud --ssh-key-file", False)
    private_key = OptString("", "Raw private SSH key; stored in a temporary 0600 file", False, advanced=True)
    target_host = OptString("", "Direct SSH host/IP; skips Compute API lookup when set", False)
    ssh_port = OptInteger(22, "Direct SSH port for backend=python", False)
    resolve_instance_ip = OptBool(True, "Resolve instance IP through Compute API before direct SSH", False)
    use_iap = OptBool(False, "Use Identity-Aware Proxy TCP tunneling", False)
    internal_ip = OptBool(False, "Use the VM internal IP address", False)
    ssh_flags = OptString("", "Comma-separated extra --ssh-flag values", False, advanced=True)
    test_command = OptString("id", "Command used to verify the session", False)
    timeout = OptInteger(120, "Command/API timeout in seconds", False, advanced=True)

    @staticmethod
    def _as_bool(value):
        raw = getattr(value, "value", value)
        if isinstance(raw, bool):
            return raw
        return str(raw).strip().lower() in ("1", "true", "yes", "y", "on")

    @staticmethod
    def _as_str(value):
        raw = getattr(value, "value", value)
        return str(raw or "").strip()

    def _service_account_search_dirs(self):
        dirs = []
        seen = set()

        def add_dir(path):
            if not path:
                return
            abs_path = os.path.abspath(path)
            if abs_path in seen:
                return
            seen.add(abs_path)
            dirs.append(abs_path)

        key_file = self._as_str(self.private_key_file)
        if key_file:
            if os.path.isfile(key_file):
                key_dir = os.path.dirname(os.path.abspath(key_file))
                add_dir(key_dir)
                add_dir(os.path.dirname(key_dir))
            elif os.path.isdir(key_file):
                add_dir(key_file)

        add_dir(os.getcwd())
        return dirs

    def _resolve_service_account_file(self):
        candidates = []
        configured = self._as_str(self.service_account_file)
        if configured:
            candidates.append(configured)
        env_path = os.environ.get("GOOGLE_APPLICATION_CREDENTIALS", "").strip()
        if env_path:
            candidates.append(env_path)
        for directory in self._service_account_search_dirs():
            for name in _DEFAULT_SERVICE_ACCOUNT_FILES:
                candidates.append(os.path.join(directory, name))
        seen = set()
        for path in candidates:
            if not path or path in seen:
                continue
            seen.add(path)
            if os.path.isfile(path):
                return path
        return ""

    @staticmethod
    def _normalize_service_account_info(info):
        if not isinstance(info, dict):
            return info
        private_key = info.get("private_key")
        if isinstance(private_key, str) and "\\n" in private_key:
            info = dict(info)
            info["private_key"] = private_key.replace("\\n", "\n")
        return info

    def _prepare_access_token_file(self):
        token_file = self._as_str(self.access_token_file)
        if token_file:
            return token_file, False

        token = self._as_str(self.access_token)
        if not token:
            token = self._mint_service_account_access_token()
        if not token:
            return "", False

        fd, path = tempfile.mkstemp(prefix="kitty-gcp-token-", text=True)
        try:
            os.fchmod(fd, 0o600)
            os.write(fd, token.encode("utf-8"))
            if not token.endswith("\n"):
                os.write(fd, b"\n")
        finally:
            os.close(fd)
        return path, True

    def _mint_service_account_access_token(self):
        service_account_file = self._resolve_service_account_file()
        service_account_json = self._as_str(self.service_account_json)
        if not service_account_file and not service_account_json:
            return ""

        try:
            from google.auth.transport.requests import Request
            from google.oauth2 import service_account
        except ImportError:
            raise RuntimeError("google-auth is required for service_account_file/service_account_json auth")

        scopes = [scope.strip() for scope in self._as_str(self.auth_scopes).split(",") if scope.strip()]
        if not scopes:
            scopes = ["https://www.googleapis.com/auth/cloud-platform"]

        if service_account_file:
            credentials = service_account.Credentials.from_service_account_file(
                service_account_file,
                scopes=scopes,
            )
        else:
            info = self._normalize_service_account_info(json.loads(service_account_json))
            credentials = service_account.Credentials.from_service_account_info(
                info,
                scopes=scopes,
            )
        credentials.refresh(Request())
        return credentials.token or ""

    def _get_google_auth_token(self):
        token = self._as_str(self.access_token)
        if token:
            return token

        token_file = self._as_str(self.access_token_file)
        if token_file:
            with open(token_file, "r", encoding="utf-8") as handle:
                return handle.read().strip()

        token = self._mint_service_account_access_token()
        if token:
            return token

        tried = []
        for path in (
            self._as_str(self.service_account_file),
            os.environ.get("GOOGLE_APPLICATION_CREDENTIALS", "").strip(),
        ):
            if path:
                tried.append(path)
        for directory in self._service_account_search_dirs():
            for name in _DEFAULT_SERVICE_ACCOUNT_FILES:
                tried.append(os.path.join(directory, name))
        hint = (
            "Set service_account_file (ex: /home/.../service-account.json), "
            "export GOOGLE_APPLICATION_CREDENTIALS, or set target_host to skip Compute API lookup"
        )
        if tried:
            hint = f"No credentials file found (checked: {', '.join(tried[:6])}{'...' if len(tried) > 6 else ''}). {hint}"

        try:
            import google.auth
            from google.auth.exceptions import DefaultCredentialsError
            from google.auth.transport.requests import Request
        except ImportError:
            raise RuntimeError(hint) from None

        scopes = [scope.strip() for scope in self._as_str(self.auth_scopes).split(",") if scope.strip()]
        if not scopes:
            scopes = ["https://www.googleapis.com/auth/cloud-platform"]
        try:
            credentials, _project = google.auth.default(scopes=scopes)
            credentials.refresh(Request())
            return credentials.token or ""
        except DefaultCredentialsError:
            raise RuntimeError(hint) from None

    def _resolve_instance_host(self, project_id, zone, instance_name):
        direct_host = self._as_str(self.target_host)
        if direct_host:
            return direct_host

        if not self._as_bool(self.resolve_instance_ip):
            return instance_name

        try:
            token = self._get_google_auth_token()
        except Exception as e:
            print_warning(
                f"Compute API lookup unavailable ({e}). "
                f"Falling back to direct SSH target '{instance_name}'. "
                "Set target_host to an IP/hostname if this name is not resolvable."
            )
            return instance_name
        if not token:
            print_warning(
                f"No GCP API token available. Falling back to direct SSH target '{instance_name}'. "
                "Set target_host to an IP/hostname if this name is not resolvable."
            )
            return instance_name

        import requests

        url = (
            "https://compute.googleapis.com/compute/v1/projects/"
            f"{project_id}/zones/{zone}/instances/{instance_name}"
        )
        response = requests.get(
            url,
            headers={"Authorization": f"Bearer {token}"},
            timeout=int(self.timeout),
        )
        if response.status_code >= 400:
            raise RuntimeError(f"Compute API lookup failed: HTTP {response.status_code} {response.text[:500]}")
        data = response.json()
        interfaces = data.get("networkInterfaces") or []
        if not interfaces:
            raise RuntimeError("Compute API returned no network interfaces")
        if self._as_bool(self.internal_ip):
            host = interfaces[0].get("networkIP")
        else:
            access_configs = interfaces[0].get("accessConfigs") or []
            host = access_configs[0].get("natIP") if access_configs else ""
        if not host:
            raise RuntimeError("Could not resolve VM IP; set target_host or enable internal_ip with network access")
        return host

    def _prepare_private_key_file(self):
        key_file = self._as_str(self.private_key_file)
        if key_file:
            return key_file, False

        key = self._as_str(self.private_key)
        if not key:
            return "", False

        fd, path = tempfile.mkstemp(prefix="kitty-gcp-ssh-key-", text=True)
        try:
            os.fchmod(fd, 0o600)
            os.write(fd, key.encode("utf-8"))
            if not key.endswith("\n"):
                os.write(fd, b"\n")
        finally:
            os.close(fd)
        return path, True

    def run(self, background=False):
        project_id = self._as_str(self.project_id)
        zone = self._as_str(self.zone)
        instance_name = self._as_str(self.instance_name)
        backend = self._as_str(self.backend) or "auto"
        flags = [flag.strip() for flag in self._as_str(self.ssh_flags).split(",") if flag.strip()]
        token_file, owns_token_file = "", False
        key_file, owns_key_file = self._prepare_private_key_file()
        conn = None

        try:
            if backend == "auto":
                backend = "gcloud" if shutil.which("gcloud") else "python"

            if backend == "gcloud":
                if not shutil.which("gcloud"):
                    print_error("gcloud CLI is required for backend=gcloud. Use backend=python for direct SSH.")
                    return False
                token_file, owns_token_file = self._prepare_access_token_file()
                sa_file = self._resolve_service_account_file()
                if sa_file and not self._as_str(self.service_account_file):
                    print_status(f"Using service account credentials from {sa_file}")
                conn = GcpComputeSshConnection(
                    project_id=project_id,
                    zone=zone,
                    instance_name=instance_name,
                    ssh_username=self._as_str(self.ssh_username),
                    account=self._as_str(self.account),
                    configuration=self._as_str(self.configuration),
                    impersonate_service_account=self._as_str(self.impersonate_service_account),
                    access_token_file=token_file,
                    owns_access_token_file=owns_token_file,
                    private_key_file=key_file,
                    owns_private_key_file=owns_key_file,
                    use_iap=self._as_bool(self.use_iap),
                    internal_ip=self._as_bool(self.internal_ip),
                    ssh_flags=flags,
                    timeout=int(self.timeout),
                )
                target = instance_name
            else:
                if self._as_bool(self.use_iap):
                    if owns_key_file:
                        try:
                            os.unlink(key_file)
                        except OSError:
                            pass
                    print_error("backend=python does not support IAP tunneling yet. Install gcloud or set backend=gcloud.")
                    return False
                sa_file = self._resolve_service_account_file()
                if sa_file and not self._as_str(self.service_account_file):
                    print_status(f"Using service account credentials from {sa_file}")
                target = self._resolve_instance_host(project_id, zone, instance_name)
                conn = GcpParamikoSshConnection(
                    host=target,
                    port=int(self.ssh_port),
                    username=self._as_str(self.ssh_username),
                    private_key_file=key_file,
                    owns_private_key_file=owns_key_file,
                    timeout=int(self.timeout),
                )

            print_status(f"Testing GCP Compute SSH on instance {instance_name}...")
            output = conn.run_command(self._as_str(self.test_command) or "id")
            if output:
                print_info(output[:4000])
            print_success("GCP Compute SSH session ready")
            return (
                conn,
                instance_name,
                int(self.ssh_port) if backend == "python" else 22,
                {
                    "instance_name": instance_name,
                    "target_host": target,
                    "project_id": project_id,
                    "zone": zone,
                    "ssh_username": self._as_str(self.ssh_username),
                    "account": self._as_str(self.account),
                    "backend": backend,
                    "private_key_file": key_file,
                    "use_iap": self._as_bool(self.use_iap),
                    "internal_ip": self._as_bool(self.internal_ip),
                    "session_type": "gcp_compute_ssh",
                    "protocol": "gcp_compute_ssh",
                },
                )
        except Exception as e:
            if conn:
                conn.close()
            elif owns_key_file and key_file:
                try:
                    os.unlink(key_file)
                except OSError:
                    pass
            print_error(f"GCP Compute SSH failed: {e}")
            return False
