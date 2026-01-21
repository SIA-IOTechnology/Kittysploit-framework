#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
SNMP Client Library for KittySploit (usable implementation)
Supports SNMP v1 / v2c:
- get(oid)
- get_next(oid)
- walk(oid, max_results)
- system/network/snmp stats helpers
- enumerate_communities(list)
"""

from dataclasses import dataclass
from typing import Dict, List, Any, Optional, Tuple
import logging
import time

from pysnmp.hlapi import (
    SnmpEngine,
    CommunityData,
    UdpTransportTarget,
    ContextData,
    ObjectType,
    ObjectIdentity,
    getCmd,
    nextCmd,
)

logger = logging.getLogger(__name__)


@dataclass
class SNMPMessage:
    version: int
    community: str
    pdu_type: int
    request_id: int
    error_status: int
    error_index: int
    variable_bindings: List[Tuple[str, Any]]


class SNMPClient:
    # “versions” cohérentes avec ton code initial
    V1 = 0
    V2C = 1

    # OIDs communs
    OIDS = {
        'system_description': '1.3.6.1.2.1.1.1.0',
        'system_uptime': '1.3.6.1.2.1.1.3.0',
        'system_contact': '1.3.6.1.2.1.1.4.0',
        'system_name': '1.3.6.1.2.1.1.5.0',
        'system_location': '1.3.6.1.2.1.1.6.0',
        'system_services': '1.3.6.1.2.1.1.7.0',
        'interfaces_number': '1.3.6.1.2.1.2.1.0',
        'ip_forwarding': '1.3.6.1.2.1.4.1.0',
        'tcp_connections': '1.3.6.1.2.1.6.1.0',
        'udp_listeners': '1.3.6.1.2.1.7.1.0',
        'snmp_in_packets': '1.3.6.1.2.1.11.1.0',
        'snmp_out_packets': '1.3.6.1.2.1.11.2.0',
    }

    def __init__(
        self,
        host: str,
        port: int = 161,
        community: str = "public",
        version: int = V2C,
        timeout: int = 5,
        retries: int = 1,
    ):
        self.host = host
        self.port = port
        self.community = community
        self.version = version
        self.timeout = timeout
        self.retries = retries
        self.logger = logger

        # engine réutilisable
        self._engine = SnmpEngine()

    def _community_data(self):
        # mpModel=0 => SNMPv1, mpModel=1 => SNMPv2c
        mp_model = 0 if self.version == self.V1 else 1
        return CommunityData(self.community, mpModel=mp_model)

    def _target(self):
        return UdpTransportTarget(
            (self.host, self.port),
            timeout=self.timeout,
            retries=self.retries,
        )

    @staticmethod
    def _pretty_value(val) -> Any:
        """
        Convert pysnmp types to python-ish values (best effort).
        """
        try:
            # ex: Integer, OctetString, ObjectIdentifier...
            if hasattr(val, "prettyPrint"):
                return val.prettyPrint()
        except Exception:
            pass
        return val

    def get(self, oid: str) -> Optional[Any]:
        """
        SNMP GET for one OID.
        Returns the value or None.
        """
        try:
            iterator = getCmd(
                self._engine,
                self._community_data(),
                self._target(),
                ContextData(),
                ObjectType(ObjectIdentity(oid)),
            )

            error_indication, error_status, error_index, var_binds = next(iterator)

            if error_indication:
                self.logger.warning(f"SNMP GET error: {error_indication}")
                return None
            if error_status:
                self.logger.warning(
                    f"SNMP GET errorStatus={error_status.prettyPrint()} at index={error_index}"
                )
                return None

            # one varbind
            for name, val in var_binds:
                return self._pretty_value(val)

            return None

        except StopIteration:
            return None
        except Exception as e:
            self.logger.error(f"SNMP GET failed for OID {oid}: {e}")
            return None

    def get_next(self, oid: str) -> Optional[Tuple[str, Any]]:
        """
        SNMP GET-NEXT for one step.
        Returns (next_oid, value) or None.
        """
        try:
            iterator = nextCmd(
                self._engine,
                self._community_data(),
                self._target(),
                ContextData(),
                ObjectType(ObjectIdentity(oid)),
                lexicographicMode=False,
                maxRows=1,
            )

            error_indication, error_status, error_index, var_binds = next(iterator)

            if error_indication:
                self.logger.warning(f"SNMP GET-NEXT error: {error_indication}")
                return None
            if error_status:
                self.logger.warning(
                    f"SNMP GET-NEXT errorStatus={error_status.prettyPrint()} at index={error_index}"
                )
                return None

            for name, val in var_binds:
                return (name.prettyPrint(), self._pretty_value(val))

            return None

        except StopIteration:
            return None
        except Exception as e:
            self.logger.error(f"SNMP GET-NEXT failed for OID {oid}: {e}")
            return None

    def walk(self, oid: str, max_results: int = 100) -> Dict[str, Any]:
        """
        SNMP WALK (GET-NEXT loop).
        Returns dict oid->value (up to max_results).
        """
        results: Dict[str, Any] = {}
        try:
            iterator = nextCmd(
                self._engine,
                self._community_data(),
                self._target(),
                ContextData(),
                ObjectType(ObjectIdentity(oid)),
                lexicographicMode=False,
                maxRows=max_results,
            )

            for error_indication, error_status, error_index, var_binds in iterator:
                if error_indication:
                    self.logger.warning(f"SNMP WALK error: {error_indication}")
                    break
                if error_status:
                    self.logger.warning(
                        f"SNMP WALK errorStatus={error_status.prettyPrint()} at index={error_index}"
                    )
                    break

                for name, val in var_binds:
                    name_s = name.prettyPrint()
                    if not name_s.startswith(oid):
                        return results
                    results[name_s] = self._pretty_value(val)

                time.sleep(0.01)

            return results

        except Exception as e:
            self.logger.error(f"SNMP WALK failed for OID {oid}: {e}")
            return results

    def get_system_info(self) -> Dict[str, Any]:
        info = {}
        for key, oid in self.OIDS.items():
            if key.startswith("system_"):
                v = self.get(oid)
                if v is not None:
                    info[key] = v
        return info

    def get_network_info(self) -> Dict[str, Any]:
        info = {}
        for key in ["interfaces_number", "ip_forwarding", "tcp_connections", "udp_listeners"]:
            oid = self.OIDS.get(key)
            if oid:
                v = self.get(oid)
                if v is not None:
                    info[key] = v
        return info

    def get_snmp_stats(self) -> Dict[str, Any]:
        stats = {}
        for key, oid in self.OIDS.items():
            if key.startswith("snmp_"):
                v = self.get(oid)
                if v is not None:
                    stats[key] = v
        return stats

    def enumerate_communities(self, communities: List[str]) -> List[str]:
        valid = []
        original = self.community
        try:
            for c in communities:
                self.community = c
                if self.get(self.OIDS["system_description"]) is not None:
                    valid.append(c)
                    self.logger.info(f"Valid community found: {c}")
        finally:
            self.community = original
        return valid

    def test_connectivity(self) -> bool:
        return self.get(self.OIDS["system_description"]) is not None


class Snmp_client(BaseModule):
    snmp_host = OptString("", "Target IP or hostname", True)
    snmp_port = OptPort(161, "Target SNMP port", True)
    snmp_community = OptString("public", "Target SNMP community", True)
    snmp_version = OptChoice("2", "Target SNMP version", True, choices=["1", "2"])
    snmp_timeout = OptPort(5, "Target SNMP timeout", True, advanced=True)
    snmp_retries = OptPort(1, "Target SNMP retries", True, advanced=True)

    def __init__(self, framework=None):
        super().__init__(framework)
    
    def open_snmp(self) -> SNMPClient:
        """
        Returns a configured SNMPClient instance.
        """
        # Convert user-friendly version to SNMPClient constants
        if self.snmp_version.value == 1:
            version = SNMPClient.V1
        else:
            version = SNMPClient.V2C

        client = SNMPClient(host=self.snmp_host.value, port=self.snmp_port.value, community=self.snmp_community.value, version=version, timeout=int(self.snmp_timeout.value), retries=int(self.snmp_retries.value))

        return client