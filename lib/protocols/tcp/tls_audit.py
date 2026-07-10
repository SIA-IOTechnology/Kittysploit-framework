#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Live TLS/SSL service audit helpers."""

from __future__ import annotations

import hashlib
import ipaddress
import socket
import ssl
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable, Dict, List, Optional, Tuple

from cryptography import x509
from cryptography.x509.oid import ExtensionOID, NameOID

from lib.protocols.tcp.tls_heartbeat import STARTTLS_PORTS, _negotiate_starttls

LogFn = Callable[[str], None]

WEAK_CIPHER_MARKERS = (
    "NULL",
    "EXPORT",
    "RC4",
    "DES",
    "3DES",
    "IDEA",
    "SEED",
    "MD5",
    "anon",
    "ADH",
    "AECDH",
)

DEPRECATED_TLS_VERSIONS = {"SSLv3", "TLSv1", "TLSv1.0", "TLSv1.1"}

VERSION_PROBE_SPECS: Tuple[Tuple[str, Optional[ssl.TLSVersion], Optional[ssl.TLSVersion]], ...] = (
    ("TLSv1.0", ssl.TLSVersion.TLSv1, ssl.TLSVersion.TLSv1),
    ("TLSv1.1", ssl.TLSVersion.TLSv1_1, ssl.TLSVersion.TLSv1_1),
    ("TLSv1.2", ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_2),
    ("TLSv1.3", ssl.TLSVersion.TLSv1_3, ssl.TLSVersion.TLSv1_3),
)


def _noop_log(_message: str) -> None:
    return None


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _name_value(name: x509.Name, oid) -> str:
    try:
        return str(name.get_attributes_for_oid(oid)[0].value)
    except Exception:
        return ""


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _hostname_matches(hostname: str, sans: List[str], common_name: str) -> bool:
    if not hostname or _is_ip(hostname):
        return True
    host = hostname.lower().rstrip(".")
    cn = (common_name or "").lower().rstrip(".")
    if cn and (cn == host or (cn.startswith("*.") and host.endswith(cn[1:]))):
        return True
    for raw in sans:
        san = str(raw).lower().rstrip(".")
        if san.startswith("*."):
            suffix = san[1:]
            if host.endswith(suffix) and host != suffix.lstrip("."):
                return True
        elif san == host:
            return True
    return False


def _parse_certificate(der: bytes) -> Dict:
    cert = x509.load_der_x509_certificate(der)
    subject_cn = _name_value(cert.subject, NameOID.COMMON_NAME)
    issuer_cn = _name_value(cert.issuer, NameOID.COMMON_NAME)
    sans: List[str] = []
    try:
        ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        sans = [str(v) for v in ext.value.get_values_for_type(x509.DNSName)]
    except x509.ExtensionNotFound:
        pass

    public_key = cert.public_key()
    key_type = type(public_key).__name__
    key_bits = getattr(public_key, "key_size", None)

    not_before = cert.not_valid_before
    not_after = cert.not_valid_after
    if not_before.tzinfo is None:
        not_before = not_before.replace(tzinfo=timezone.utc)
    else:
        not_before = not_before.astimezone(timezone.utc)
    if not_after.tzinfo is None:
        not_after = not_after.replace(tzinfo=timezone.utc)
    else:
        not_after = not_after.astimezone(timezone.utc)
    days_until_expiry = (not_after - _utc_now()).days

    return {
        "subject_cn": subject_cn,
        "issuer_cn": issuer_cn,
        "subject_dn": cert.subject.rfc4514_string(),
        "issuer_dn": cert.issuer.rfc4514_string(),
        "serial_number": format(cert.serial_number, "x"),
        "not_before": not_before.isoformat(),
        "not_after": not_after.isoformat(),
        "days_until_expiry": days_until_expiry,
        "expired": days_until_expiry < 0,
        "self_signed": cert.issuer == cert.subject,
        "san_dns": sans,
        "fingerprint_sha256": hashlib.sha256(der).hexdigest(),
        "signature_algorithm": cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else "",
        "key_type": key_type,
        "key_bits": key_bits,
    }


def _client_context(
    *,
    verify: bool,
    min_version: Optional[ssl.TLSVersion] = None,
    max_version: Optional[ssl.TLSVersion] = None,
) -> ssl.SSLContext:
    if verify:
        ctx = ssl.create_default_context()
    else:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    if min_version is not None:
        ctx.minimum_version = min_version
    if max_version is not None:
        ctx.maximum_version = max_version
    return ctx


def _connect_tls(
    host: str,
    port: int,
    server_name: str,
    timeout: float,
    *,
    verify: bool,
    use_starttls: bool,
    auto_starttls: bool,
    min_version: Optional[ssl.TLSVersion] = None,
    max_version: Optional[ssl.TLSVersion] = None,
    log: LogFn = _noop_log,
) -> Tuple[Optional[ssl.SSLSocket], Optional[str]]:
    ctx = _client_context(verify=verify, min_version=min_version, max_version=max_version)
    raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    raw.settimeout(timeout)
    try:
        raw.connect((host, port))
        if use_starttls or (auto_starttls and port in STARTTLS_PORTS):
            if not _negotiate_starttls(raw, port, timeout, log=log):
                raw.close()
                return None, "STARTTLS negotiation failed"
        tls_sock = ctx.wrap_socket(raw, server_hostname=server_name or host)
        return tls_sock, None
    except ssl.SSLError as exc:
        try:
            raw.close()
        except Exception:
            pass
        return None, str(exc)
    except OSError as exc:
        try:
            raw.close()
        except Exception:
            pass
        return None, str(exc)


def _cipher_bits(cipher: Tuple[str, str, int]) -> int:
    if not cipher:
        return 0
    try:
        return int(cipher[2])
    except (TypeError, ValueError):
        return 0


def _is_weak_cipher(cipher_name: str) -> bool:
    upper = (cipher_name or "").upper()
    return any(marker in upper for marker in WEAK_CIPHER_MARKERS)


def _probe_supported_versions(
    host: str,
    port: int,
    server_name: str,
    timeout: float,
    *,
    use_starttls: bool,
    auto_starttls: bool,
    log: LogFn = _noop_log,
) -> List[str]:
    supported: List[str] = []
    for label, min_ver, max_ver in VERSION_PROBE_SPECS:
        tls_sock, error = _connect_tls(
            host,
            port,
            server_name,
            timeout,
            verify=False,
            use_starttls=use_starttls,
            auto_starttls=auto_starttls,
            min_version=min_ver,
            max_version=max_ver,
            log=log,
        )
        if tls_sock is None:
            log(f"{label}: not supported ({error})")
            continue
        try:
            negotiated = tls_sock.version() or label
            supported.append(negotiated)
            log(f"{label}: supported ({negotiated})")
        finally:
            try:
                tls_sock.close()
            except Exception:
                pass
    return sorted(set(supported))


def _assess_findings(
    *,
    certificate: Dict,
    tls_version: str,
    cipher_name: str,
    server_name: str,
    verify_ssl: bool,
    verify_error: str,
    supported_versions: List[str],
) -> Tuple[List[Dict], int]:
    findings: List[Dict] = []
    score = 0

    if certificate.get("expired"):
        findings.append({
            "type": "expired_certificate",
            "severity": "high",
            "description": "Certificate is expired",
        })
        score += 5
    else:
        days = certificate.get("days_until_expiry", 999)
        if days <= 7:
            findings.append({
                "type": "certificate_expiring_soon",
                "severity": "high",
                "description": f"Certificate expires in {days} day(s)",
            })
            score += 3
        elif days <= 30:
            findings.append({
                "type": "certificate_expiring_soon",
                "severity": "medium",
                "description": f"Certificate expires in {days} day(s)",
            })
            score += 1

    if certificate.get("self_signed"):
        findings.append({
            "type": "self_signed_certificate",
            "severity": "medium",
            "description": "Certificate appears self-signed (issuer equals subject)",
        })
        score += 3

    if server_name and not _hostname_matches(
        server_name,
        certificate.get("san_dns", []),
        certificate.get("subject_cn", ""),
    ):
        findings.append({
            "type": "hostname_mismatch",
            "severity": "high",
            "description": f"SNI hostname '{server_name}' not covered by certificate SAN/CN",
        })
        score += 4

    if _is_weak_cipher(cipher_name):
        findings.append({
            "type": "weak_cipher",
            "severity": "high",
            "description": f"Negotiated weak cipher suite: {cipher_name}",
        })
        score += 4

    if tls_version in DEPRECATED_TLS_VERSIONS:
        findings.append({
            "type": "deprecated_tls_version",
            "severity": "high",
            "description": f"Negotiated deprecated TLS version: {tls_version}",
        })
        score += 3

    for version in supported_versions:
        if version in DEPRECATED_TLS_VERSIONS and version != tls_version:
            findings.append({
                "type": "legacy_tls_supported",
                "severity": "medium",
                "description": f"Server accepts deprecated TLS version: {version}",
            })
            score += 2

    key_bits = certificate.get("key_bits")
    if isinstance(key_bits, int) and key_bits < 2048:
        findings.append({
            "type": "weak_key_size",
            "severity": "medium",
            "description": f"Certificate public key is only {key_bits} bits",
        })
        score += 2

    if verify_ssl and verify_error:
        findings.append({
            "type": "certificate_verify_failed",
            "severity": "high",
            "description": verify_error,
        })
        score += 4

    return findings, min(10, score)


@dataclass
class TlsAuditResult:
    host: str
    port: int
    server_name: str
    success: bool
    error: str = ""
    tls_version: str = ""
    cipher: str = ""
    cipher_bits: int = 0
    certificate: Dict = field(default_factory=dict)
    supported_versions: List[str] = field(default_factory=list)
    verify_ssl: bool = False
    verify_ok: bool = False
    verify_error: str = ""
    findings: List[Dict] = field(default_factory=list)
    risk_score: int = 0
    risk_level: str = "LOW"

    def to_dict(self) -> Dict:
        return {
            "host": self.host,
            "port": self.port,
            "server_name": self.server_name,
            "success": self.success,
            "error": self.error,
            "tls_version": self.tls_version,
            "cipher": self.cipher,
            "cipher_bits": self.cipher_bits,
            "certificate": self.certificate,
            "supported_versions": self.supported_versions,
            "verify_ssl": self.verify_ssl,
            "verify_ok": self.verify_ok,
            "verify_error": self.verify_error,
            "findings": self.findings,
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
        }


def audit_tls_service(
    host: str,
    port: int,
    *,
    server_name: str = "",
    timeout: float = 10.0,
    verify_ssl: bool = False,
    probe_versions: bool = True,
    use_starttls: bool = False,
    auto_starttls: bool = True,
    log: LogFn = _noop_log,
) -> TlsAuditResult:
    """Perform a live TLS audit against host:port."""
    sni = (server_name or host).strip()
    result = TlsAuditResult(host=host, port=port, server_name=sni, success=False, verify_ssl=verify_ssl)

    tls_sock, error = _connect_tls(
        host,
        port,
        sni,
        timeout,
        verify=verify_ssl,
        use_starttls=use_starttls,
        auto_starttls=auto_starttls,
        log=log,
    )
    if tls_sock is None:
        result.error = error or "TLS handshake failed"
        return result

    verify_error = ""
    verify_ok = not verify_ssl
    try:
        cipher = tls_sock.cipher() or ("", "", 0)
        result.tls_version = tls_sock.version() or ""
        result.cipher = cipher[0]
        result.cipher_bits = _cipher_bits(cipher)

        der = tls_sock.getpeercert(binary_form=True)
        if not der:
            result.error = "No peer certificate returned"
            return result
        result.certificate = _parse_certificate(der)
        result.success = True
    except ssl.SSLError as exc:
        result.error = str(exc)
        verify_error = str(exc)
        verify_ok = False
        return result
    finally:
        try:
            tls_sock.close()
        except Exception:
            pass

    if verify_ssl:
        verify_sock, verify_connect_error = _connect_tls(
            host,
            port,
            sni,
            timeout,
            verify=True,
            use_starttls=use_starttls,
            auto_starttls=auto_starttls,
            log=log,
        )
        if verify_sock is None:
            verify_ok = False
            verify_error = verify_connect_error or "Certificate verification failed"
        else:
            verify_ok = True
            try:
                verify_sock.close()
            except Exception:
                pass

    supported_versions: List[str] = []
    if probe_versions:
        supported_versions = _probe_supported_versions(
            host,
            port,
            sni,
            timeout,
            use_starttls=use_starttls,
            auto_starttls=auto_starttls,
            log=log,
        )
        if result.tls_version and result.tls_version not in supported_versions:
            supported_versions.append(result.tls_version)
            supported_versions = sorted(set(supported_versions))

    findings, risk_score = _assess_findings(
        certificate=result.certificate,
        tls_version=result.tls_version,
        cipher_name=result.cipher,
        server_name=sni,
        verify_ssl=verify_ssl,
        verify_error=verify_error,
        supported_versions=supported_versions,
    )
    result.supported_versions = supported_versions
    result.verify_ok = verify_ok
    result.verify_error = verify_error
    result.findings = findings
    result.risk_score = risk_score
    result.risk_level = "LOW" if risk_score <= 2 else ("MEDIUM" if risk_score <= 5 else "HIGH")
    return result


@dataclass
class CipherSuiteEntry:
    name: str
    tls_version: str
    bits: int = 0
    weak: bool = False


@dataclass
class CipherEnumerationResult:
    host: str
    port: int
    server_name: str
    success: bool
    error: str = ""
    accepted_ciphers: List[CipherSuiteEntry] = field(default_factory=list)
    weak_ciphers: List[str] = field(default_factory=list)
    supported_versions: List[str] = field(default_factory=list)
    risk_score: int = 0
    risk_level: str = "LOW"

    def to_dict(self) -> Dict:
        return {
            "host": self.host,
            "port": self.port,
            "server_name": self.server_name,
            "success": self.success,
            "error": self.error,
            "accepted_ciphers": [
                {
                    "name": c.name,
                    "tls_version": c.tls_version,
                    "bits": c.bits,
                    "weak": c.weak,
                }
                for c in self.accepted_ciphers
            ],
            "weak_ciphers": self.weak_ciphers,
            "supported_versions": self.supported_versions,
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
        }


def _try_single_cipher(
    host: str,
    port: int,
    server_name: str,
    timeout: float,
    cipher_name: str,
    min_version: Optional[ssl.TLSVersion],
    max_version: Optional[ssl.TLSVersion],
    *,
    use_starttls: bool,
    auto_starttls: bool,
    log: LogFn = _noop_log,
) -> Optional[CipherSuiteEntry]:
    ctx = _client_context(verify=False, min_version=min_version, max_version=max_version)
    for spec in (cipher_name, f"{cipher_name}:@SECLEVEL=0"):
        try:
            ctx.set_ciphers(spec)
        except ssl.SSLError:
            continue
        tls_sock, _error = _connect_tls(
            host,
            port,
            server_name,
            timeout,
            verify=False,
            use_starttls=use_starttls,
            auto_starttls=auto_starttls,
            log=log,
        )
        if tls_sock is None:
            continue
        try:
            negotiated = tls_sock.cipher() or (cipher_name, "", 0)
            version = tls_sock.version() or ""
            name = negotiated[0] or cipher_name
            bits = _cipher_bits(negotiated)
            weak = _is_weak_cipher(name)
            log(f"accepted {version} {name}")
            return CipherSuiteEntry(name=name, tls_version=version, bits=bits, weak=weak)
        finally:
            try:
                tls_sock.close()
            except Exception:
                pass
    return None


def enumerate_cipher_suites(
    host: str,
    port: int,
    *,
    server_name: str = "",
    timeout: float = 10.0,
    max_ciphers: int = 80,
    use_starttls: bool = False,
    auto_starttls: bool = True,
    log: LogFn = _noop_log,
) -> CipherEnumerationResult:
    """Enumerate cipher suites accepted by the remote TLS endpoint."""
    sni = (server_name or host).strip()
    result = CipherEnumerationResult(host=host, port=port, server_name=sni, success=False)

    probe_ctx = _client_context(verify=False)
    try:
        candidates = probe_ctx.get_ciphers()
    except Exception as exc:
        result.error = f"Unable to list local cipher candidates: {exc}"
        return result

    seen = set()
    for entry in candidates[: max(1, max_ciphers)]:
        cipher_name = str(entry.get("name") or "").strip()
        if not cipher_name or cipher_name in seen:
            continue
        seen.add(cipher_name)
        accepted = _try_single_cipher(
            host,
            port,
            sni,
            timeout,
            cipher_name,
            None,
            None,
            use_starttls=use_starttls,
            auto_starttls=auto_starttls,
            log=log,
        )
        if accepted:
            result.accepted_ciphers.append(accepted)

    if not result.accepted_ciphers:
        result.error = "No cipher suites accepted during enumeration"
        return result

    result.success = True
    result.weak_ciphers = sorted({c.name for c in result.accepted_ciphers if c.weak})
    result.supported_versions = sorted({c.tls_version for c in result.accepted_ciphers if c.tls_version})

    score = 0
    if result.weak_ciphers:
        score += min(6, len(result.weak_ciphers) * 2)
    if any(v in DEPRECATED_TLS_VERSIONS for v in result.supported_versions):
        score += 2
    result.risk_score = min(10, score)
    result.risk_level = "LOW" if score <= 2 else ("MEDIUM" if score <= 5 else "HIGH")
    return result
