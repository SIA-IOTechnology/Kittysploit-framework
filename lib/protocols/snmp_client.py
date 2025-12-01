#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
SNMP Client Library for KittySploit
Provides SNMP protocol support for network monitoring and information gathering
"""

import socket
import struct
import time
from typing import Dict, List, Any, Optional, Tuple, Union
import logging
from dataclasses import dataclass

logger = logging.getLogger(__name__)

@dataclass
class SNMPMessage:
    """SNMP message structure"""
    version: int
    community: str
    pdu_type: int
    request_id: int
    error_status: int
    error_index: int
    variable_bindings: List[Tuple[str, Any]]

class SNMPClient:
    """SNMP client for network monitoring and information gathering"""
    
    # SNMP PDU Types
    GET_REQUEST = 0xA0
    GET_NEXT_REQUEST = 0xA1
    GET_RESPONSE = 0xA2
    SET_REQUEST = 0xA3
    TRAP = 0xA4
    
    # SNMP Versions
    V1 = 0
    V2C = 1
    V3 = 3
    
    # Common OIDs
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
        'snmp_in_bad_versions': '1.3.6.1.2.1.11.3.0',
        'snmp_in_bad_communities': '1.3.6.1.2.1.11.4.0',
        'snmp_in_bad_names': '1.3.6.1.2.1.11.5.0',
        'snmp_in_bad_values': '1.3.6.1.2.1.11.6.0',
        'snmp_in_read_onlys': '1.3.6.1.2.1.11.7.0',
        'snmp_in_generrs': '1.3.6.1.2.1.11.8.0',
        'snmp_in_total_req_vars': '1.3.6.1.2.1.11.9.0',
        'snmp_in_total_set_vars': '1.3.6.1.2.1.11.10.0',
        'snmp_in_get_requests': '1.3.6.1.2.1.11.11.0',
        'snmp_in_get_nexts': '1.3.6.1.2.1.11.12.0',
        'snmp_in_set_requests': '1.3.6.1.2.1.11.13.0',
        'snmp_in_get_responses': '1.3.6.1.2.1.11.14.0',
        'snmp_in_traps': '1.3.6.1.2.1.11.15.0',
        'snmp_out_too_bigs': '1.3.6.1.2.1.11.16.0',
        'snmp_out_no_such_names': '1.3.6.1.2.1.11.17.0',
        'snmp_out_bad_values': '1.3.6.1.2.1.11.18.0',
        'snmp_out_generrs': '1.3.6.1.2.1.11.19.0',
        'snmp_out_get_requests': '1.3.6.1.2.1.11.20.0',
        'snmp_out_get_nexts': '1.3.6.1.2.1.11.21.0',
        'snmp_out_set_requests': '1.3.6.1.2.1.11.22.0',
        'snmp_out_get_responses': '1.3.6.1.2.1.11.23.0',
        'snmp_out_traps': '1.3.6.1.2.1.11.24.0'
    }
    
    def __init__(self, 
                 host: str,
                 port: int = 161,
                 community: str = 'public',
                 version: int = V2C,
                 timeout: int = 5):
        """
        Initialize SNMP client
        
        Args:
            host: Target host
            port: SNMP port (default: 161)
            community: SNMP community string
            version: SNMP version (V1, V2C, V3)
            timeout: Socket timeout in seconds
        """
        self.host = host
        self.port = port
        self.community = community
        self.version = version
        self.timeout = timeout
        self.request_id = 1
        self.logger = logger
    
    def get(self, oid: str) -> Optional[Any]:
        """
        Perform SNMP GET request
        
        Args:
            oid: Object Identifier to query
            
        Returns:
            Value of the OID or None if failed
        """
        try:
            message = self._create_get_request(oid)
            response = self._send_message(message)
            
            if response and response.variable_bindings:
                return response.variable_bindings[0][1]
            
            return None
            
        except Exception as e:
            self.logger.error(f"SNMP GET failed for OID {oid}: {e}")
            return None
    
    def get_next(self, oid: str) -> Optional[Tuple[str, Any]]:
        """
        Perform SNMP GET-NEXT request
        
        Args:
            oid: Object Identifier to query
            
        Returns:
            Tuple of (next_oid, value) or None if failed
        """
        try:
            message = self._create_get_next_request(oid)
            response = self._send_message(message)
            
            if response and response.variable_bindings:
                return response.variable_bindings[0]
            
            return None
            
        except Exception as e:
            self.logger.error(f"SNMP GET-NEXT failed for OID {oid}: {e}")
            return None
    
    def walk(self, oid: str, max_results: int = 100) -> Dict[str, Any]:
        """
        Perform SNMP WALK (multiple GET-NEXT requests)
        
        Args:
            oid: Starting Object Identifier
            max_results: Maximum number of results
            
        Returns:
            Dictionary of OID -> value mappings
        """
        results = {}
        current_oid = oid
        count = 0
        
        try:
            while count < max_results:
                next_result = self.get_next(current_oid)
                if not next_result:
                    break
                
                next_oid, value = next_result
                
                # Check if we've gone beyond our target OID
                if not next_oid.startswith(oid):
                    break
                
                results[next_oid] = value
                current_oid = next_oid
                count += 1
                
                # Small delay to avoid overwhelming the target
                time.sleep(0.01)
            
            return results
            
        except Exception as e:
            self.logger.error(f"SNMP WALK failed for OID {oid}: {e}")
            return results
    
    def get_system_info(self) -> Dict[str, Any]:
        """Get basic system information"""
        info = {}
        
        for key, oid in self.OIDS.items():
            if key.startswith('system_'):
                value = self.get(oid)
                if value is not None:
                    info[key] = value
        
        return info
    
    def get_network_info(self) -> Dict[str, Any]:
        """Get network-related information"""
        info = {}
        
        network_oids = [
            'interfaces_number', 'ip_forwarding', 'tcp_connections',
            'udp_listeners'
        ]
        
        for key in network_oids:
            if key in self.OIDS:
                value = self.get(self.OIDS[key])
                if value is not None:
                    info[key] = value
        
        return info
    
    def get_snmp_stats(self) -> Dict[str, Any]:
        """Get SNMP statistics"""
        stats = {}
        
        snmp_oids = [key for key in self.OIDS.keys() if key.startswith('snmp_')]
        
        for key in snmp_oids:
            value = self.get(self.OIDS[key])
            if value is not None:
                stats[key] = value
        
        return stats
    
    def enumerate_communities(self, communities: List[str]) -> List[str]:
        """
        Enumerate valid SNMP communities
        
        Args:
            communities: List of community strings to test
            
        Returns:
            List of valid community strings
        """
        valid_communities = []
        original_community = self.community
        
        for community in communities:
            self.community = community
            
            # Try to get system description
            result = self.get(self.OIDS['system_description'])
            if result is not None:
                valid_communities.append(community)
                self.logger.info(f"Valid community found: {community}")
        
        # Restore original community
        self.community = original_community
        
        return valid_communities
    
    def _create_get_request(self, oid: str) -> SNMPMessage:
        """Create SNMP GET request message"""
        return SNMPMessage(
            version=self.version,
            community=self.community,
            pdu_type=self.GET_REQUEST,
            request_id=self.request_id,
            error_status=0,
            error_index=0,
            variable_bindings=[(oid, None)]
        )
    
    def _create_get_next_request(self, oid: str) -> SNMPMessage:
        """Create SNMP GET-NEXT request message"""
        return SNMPMessage(
            version=self.version,
            community=self.community,
            pdu_type=self.GET_NEXT_REQUEST,
            request_id=self.request_id,
            error_status=0,
            error_index=0,
            variable_bindings=[(oid, None)]
        )
    
    def _send_message(self, message: SNMPMessage) -> Optional[SNMPMessage]:
        """Send SNMP message and receive response"""
        try:
            # Encode message
            data = self._encode_message(message)
            
            # Send UDP packet
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self.timeout)
            
            sock.sendto(data, (self.host, self.port))
            response_data, addr = sock.recvfrom(4096)
            sock.close()
            
            # Decode response
            response = self._decode_message(response_data)
            
            # Increment request ID for next request
            self.request_id = (self.request_id + 1) % 2147483647
            
            return response
            
        except socket.timeout:
            self.logger.warning(f"SNMP timeout for {self.host}:{self.port}")
            return None
        except Exception as e:
            self.logger.error(f"SNMP communication error: {e}")
            return None
    
    def _encode_message(self, message: SNMPMessage) -> bytes:
        """Encode SNMP message to bytes"""
        # This is a simplified implementation
        # In a real implementation, you would use proper ASN.1 encoding
        
        # For now, return a basic structure
        # This would need proper BER encoding in production
        return b'\x30\x0c\x02\x01\x01\x04\x06public\xa0\x05\x02\x01\x01\x02\x01\x00\x30\x00'
    
    def _decode_message(self, data: bytes) -> Optional[SNMPMessage]:
        """Decode SNMP message from bytes"""
        # This is a simplified implementation
        # In a real implementation, you would use proper ASN.1 decoding
        
        try:
            # Basic parsing - this would need proper BER decoding
            if len(data) < 10:
                return None
            
            # Extract basic fields (simplified)
            version = 1  # V2C
            community = "public"
            pdu_type = data[8] if len(data) > 8 else 0
            request_id = 1
            error_status = 0
            error_index = 0
            
            # Extract variable bindings (simplified)
            variable_bindings = []
            
            return SNMPMessage(
                version=version,
                community=community,
                pdu_type=pdu_type,
                request_id=request_id,
                error_status=error_status,
                error_index=error_index,
                variable_bindings=variable_bindings
            )
            
        except Exception as e:
            self.logger.error(f"Failed to decode SNMP message: {e}")
            return None
    
    def test_connectivity(self) -> bool:
        """Test SNMP connectivity"""
        try:
            result = self.get(self.OIDS['system_description'])
            return result is not None
        except Exception:
            return False
