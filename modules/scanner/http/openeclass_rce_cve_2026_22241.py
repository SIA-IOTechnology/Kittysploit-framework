#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from bs4 import BeautifulSoup
import re

class Module(Scanner, Http_client):

    __info__ = {
        "name": "OpenEclass RCE (CVE-2026-22241) Detection",
        "description": "Detects GUnet OpenEclass instances vulnerable to Remote Code Execution (CVE-2026-22241) "
                       "by checking the platform version. Versions prior to 4.2 are vulnerable to an unrestricted "
                       "file upload in the theme import functionality.",
        "author": ["Kittysploit Team"],
        "severity": "critical",
        "cve": "CVE-2026-22241",
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2026-22241",
            "https://github.com/gunet/openeclass/security/advisories"
        ],
        "modules": [
            "exploits/http/openeclass_rce_cve_2026_22241",
        ],
        "tags": ["web", "scanner", "openeclass", "rce", "cve-2026-22241"],
    }

    def _version_lt(self, v1: str, v2: str) -> bool:
        """
        Compare two version strings
        """
        def norm(v):
            out = []
            for token in str(v).split("."):
                digits = "".join(ch for ch in token if ch.isdigit())
                out.append(int(digits) if digits else 0)
            while len(out) < 3:
                out.append(0)
            return tuple(out[:3])

        return norm(v1) < norm(v2)

    def run(self):
        """
        Execute the scanner
        """
        try:
            # Step 1: Detect OpenEclass
            response = self.http_request(method="GET", path="/")
            if not response or response.status_code != 200:
                return False

            content = response.text
            is_openeclass = False
            if 'openeclass' in content.lower() or 'open eclass' in content.lower():
                is_openeclass = True

            if not is_openeclass:
                return False

            # Step 2: Extract version
            # Common patterns: "Open eClass 4.1", "version: 4.1.2", etc.
            version = None
            
            # Try searching in the footer/content
            version_match = re.search(r'Open\s+eClass\s+([\d\.]+)', content, re.IGNORECASE)
            if version_match:
                version = version_match.group(1)
            
            if not version:
                # Try meta tags or other common places
                soup = BeautifulSoup(content, 'html.parser')
                # Sometimes it's in a generator tag or similar
                generator = soup.find('meta', {'name': 'generator'})
                if generator and 'openeclass' in generator.get('content', '').lower():
                    gen_match = re.search(r'([\d\.]+)', generator.get('content', ''))
                    if gen_match:
                        version = gen_match.group(1)

            # Step 3: Reporting
            if version:
                print_info(f"OpenEclass version {version} detected")
                if self._version_lt(version, "4.2"):
                    self.set_info(
                        severity="critical",
                        cve="CVE-2026-22241",
                        reason=f"OpenEclass version {version} is vulnerable to CVE-2026-22241 (RCE)",
                    )
                    return True
                else:
                    print_status(f"OpenEclass version {version} is not vulnerable to CVE-2026-22241")
                    return False
            else:
                # OpenEclass detected but version unknown
                self.set_info(
                    severity="medium",
                    cve="CVE-2026-22241",
                    reason="OpenEclass detected but version could not be determined. Potentially vulnerable if < 4.2.",
                )
                return True

        except Exception as e:
            print_error(f"Scanner failed: {e}")
            return False
