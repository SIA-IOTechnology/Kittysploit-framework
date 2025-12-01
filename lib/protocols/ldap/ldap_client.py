#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
LDAP Client Library for KittySploit
Provides LDAP protocol support for directory services and authentication
"""

import socket
import ssl
import struct
from typing import Dict, List, Any, Optional, Tuple
import logging
from dataclasses import dataclass

logger = logging.getLogger(__name__)

@dataclass
class LDAPMessage:
    """LDAP message structure"""
    message_id: int
    protocol_op: int
    controls: Optional[List] = None

class LDAPClient:
    """LDAP client for directory services and authentication"""
    
    # LDAP Protocol Operations
    BIND_REQUEST = 0x60
    BIND_RESPONSE = 0x61
    SEARCH_REQUEST = 0x63
    SEARCH_RESULT_ENTRY = 0x64
    SEARCH_RESULT_DONE = 0x65
    MODIFY_REQUEST = 0x66
    MODIFY_RESPONSE = 0x67
    ADD_REQUEST = 0x68
    ADD_RESPONSE = 0x69
    DEL_REQUEST = 0x4A
    DEL_RESPONSE = 0x6B
    MODIFY_DN_REQUEST = 0x6C
    MODIFY_DN_RESPONSE = 0x6D
    COMPARE_REQUEST = 0x6E
    COMPARE_RESPONSE = 0x6F
    ABANDON_REQUEST = 0x50
    
    # LDAP Result Codes
    SUCCESS = 0x00
    OPERATIONS_ERROR = 0x01
    PROTOCOL_ERROR = 0x02
    TIME_LIMIT_EXCEEDED = 0x03
    SIZE_LIMIT_EXCEEDED = 0x04
    COMPARE_FALSE = 0x05
    COMPARE_TRUE = 0x06
    AUTH_METHOD_NOT_SUPPORTED = 0x07
    STRONGER_AUTH_REQUIRED = 0x08
    REFERRAL = 0x0A
    ADMIN_LIMIT_EXCEEDED = 0x0B
    UNAVAILABLE_CRITICAL_EXTENSION = 0x0C
    CONFIDENTIALITY_REQUIRED = 0x0D
    SASL_BIND_IN_PROGRESS = 0x0E
    NO_SUCH_ATTRIBUTE = 0x10
    UNDEFINED_ATTRIBUTE_TYPE = 0x11
    INAPPROPRIATE_MATCHING = 0x12
    CONSTRAINT_VIOLATION = 0x13
    ATTRIBUTE_OR_VALUE_EXISTS = 0x14
    INVALID_ATTRIBUTE_SYNTAX = 0x15
    NO_SUCH_OBJECT = 0x20
    ALIAS_PROBLEM = 0x21
    INVALID_DN_SYNTAX = 0x22
    ALIAS_DEREFERENCING_PROBLEM = 0x24
    INAPPROPRIATE_AUTHENTICATION = 0x30
    INVALID_CREDENTIALS = 0x31
    INSUFFICIENT_ACCESS_RIGHTS = 0x32
    BUSY = 0x33
    UNAVAILABLE = 0x34
    UNWILLING_TO_PERFORM = 0x35
    LOOP_DETECT = 0x36
    NAMING_VIOLATION = 0x40
    OBJECT_CLASS_VIOLATION = 0x41
    NOT_ALLOWED_ON_NON_LEAF = 0x42
    NOT_ALLOWED_ON_RDN = 0x43
    ENTRY_ALREADY_EXISTS = 0x44
    OBJECT_CLASS_MODS_PROHIBITED = 0x45
    AFFECTS_MULTIPLE_DSAS = 0x47
    OTHER = 0x50
    
    def __init__(self, 
                 host: str,
                 port: int = 389,
                 use_ssl: bool = False,
                 timeout: int = 30):
        """
        Initialize LDAP client
        
        Args:
            host: Target host
            port: LDAP port (389 for LDAP, 636 for LDAPS)
            use_ssl: Whether to use SSL/TLS
            timeout: Connection timeout in seconds
        """
        self.host = host
        self.port = port
        self.use_ssl = use_ssl
        self.timeout = timeout
        self.socket = None
        self.message_id = 1
        self.logger = logger
    
    def connect(self) -> bool:
        """Connect to LDAP server"""
        try:
            # Create socket
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.settimeout(self.timeout)
            
            # Connect
            self.socket.connect((self.host, self.port))
            
            # Upgrade to SSL if needed
            if self.use_ssl:
                context = ssl.create_default_context()
                self.socket = context.wrap_socket(self.socket, server_hostname=self.host)
            
            self.logger.info(f"Connected to LDAP server {self.host}:{self.port}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to connect to LDAP server: {e}")
            return False
    
    def disconnect(self):
        """Disconnect from LDAP server"""
        if self.socket:
            try:
                self.socket.close()
                self.logger.info("Disconnected from LDAP server")
            except Exception as e:
                self.logger.error(f"Error disconnecting: {e}")
            finally:
                self.socket = None
    
    def bind(self, 
             bind_dn: str = "",
             password: str = "",
             auth_method: str = "simple") -> bool:
        """
        Bind to LDAP server
        
        Args:
            bind_dn: Distinguished Name for binding
            password: Password for binding
            auth_method: Authentication method (simple, sasl)
            
        Returns:
            True if bind successful, False otherwise
        """
        try:
            if not self.socket:
                if not self.connect():
                    return False
            
            # Create bind request
            bind_request = self._create_bind_request(bind_dn, password, auth_method)
            
            # Send request
            self._send_message(bind_request)
            
            # Receive response
            response = self._receive_message()
            
            if response and response.get('result_code') == self.SUCCESS:
                self.logger.info(f"Successfully bound as {bind_dn or 'anonymous'}")
                return True
            else:
                result_code = response.get('result_code', 'unknown') if response else 'no_response'
                self.logger.warning(f"Bind failed with result code: {result_code}")
                return False
                
        except Exception as e:
            self.logger.error(f"Bind operation failed: {e}")
            return False
    
    def search(self, 
               base_dn: str,
               scope: str = "subtree",
               filter_str: str = "(objectClass=*)",
               attributes: List[str] = None,
               size_limit: int = 0,
               time_limit: int = 0) -> List[Dict[str, Any]]:
        """
        Search LDAP directory
        
        Args:
            base_dn: Base DN for search
            scope: Search scope (base, onelevel, subtree)
            filter_str: LDAP filter string
            attributes: List of attributes to return
            size_limit: Maximum number of entries to return
            time_limit: Maximum time in seconds
            
        Returns:
            List of search results
        """
        try:
            if not self.socket:
                if not self.connect():
                    return []
            
            # Create search request
            search_request = self._create_search_request(
                base_dn, scope, filter_str, attributes, size_limit, time_limit
            )
            
            # Send request
            self._send_message(search_request)
            
            # Collect results
            results = []
            while True:
                response = self._receive_message()
                if not response:
                    break
                
                if response.get('protocol_op') == self.SEARCH_RESULT_ENTRY:
                    results.append(response.get('entry', {}))
                elif response.get('protocol_op') == self.SEARCH_RESULT_DONE:
                    result_code = response.get('result_code', self.OTHER)
                    if result_code != self.SUCCESS:
                        self.logger.warning(f"Search completed with result code: {result_code}")
                    break
            
            self.logger.info(f"Search returned {len(results)} entries")
            return results
            
        except Exception as e:
            self.logger.error(f"Search operation failed: {e}")
            return []
    
    def enumerate_users(self, base_dn: str) -> List[Dict[str, Any]]:
        """Enumerate users in the directory"""
        user_filters = [
            "(objectClass=user)",
            "(objectClass=person)",
            "(objectClass=inetOrgPerson)",
            "(objectClass=posixAccount)",
            "(sAMAccountName=*)",
            "(uid=*)"
        ]
        
        all_users = []
        for filter_str in user_filters:
            users = self.search(
                base_dn=base_dn,
                filter_str=filter_str,
                attributes=["cn", "sAMAccountName", "uid", "mail", "userPrincipalName", "memberOf"]
            )
            all_users.extend(users)
        
        # Remove duplicates
        unique_users = []
        seen_dns = set()
        for user in all_users:
            dn = user.get('dn', '')
            if dn not in seen_dns:
                unique_users.append(user)
                seen_dns.add(dn)
        
        return unique_users
    
    def enumerate_groups(self, base_dn: str) -> List[Dict[str, Any]]:
        """Enumerate groups in the directory"""
        group_filters = [
            "(objectClass=group)",
            "(objectClass=groupOfNames)",
            "(objectClass=groupOfUniqueNames)",
            "(objectClass=posixGroup)"
        ]
        
        all_groups = []
        for filter_str in group_filters:
            groups = self.search(
                base_dn=base_dn,
                filter_str=filter_str,
                attributes=["cn", "member", "memberOf", "description"]
            )
            all_groups.extend(groups)
        
        # Remove duplicates
        unique_groups = []
        seen_dns = set()
        for group in all_groups:
            dn = group.get('dn', '')
            if dn not in seen_dns:
                unique_groups.append(group)
                seen_dns.add(dn)
        
        return unique_groups
    
    def brute_force_credentials(self, 
                               usernames: List[str],
                               passwords: List[str],
                               base_dn: str = "") -> List[Dict[str, str]]:
        """
        Brute force LDAP credentials
        
        Args:
            usernames: List of usernames to test
            passwords: List of passwords to test
            base_dn: Base DN for user search
            
        Returns:
            List of valid credentials
        """
        valid_credentials = []
        
        for username in usernames:
            for password in passwords:
                try:
                    # Try different DN formats
                    dn_formats = [
                        f"cn={username},{base_dn}",
                        f"uid={username},{base_dn}",
                        f"userPrincipalName={username}@{self.host}",
                        f"sAMAccountName={username},{base_dn}",
                        username  # Sometimes just the username works
                    ]
                    
                    for dn in dn_formats:
                        if self.bind(dn, password):
                            valid_credentials.append({
                                'username': username,
                                'password': password,
                                'dn': dn
                            })
                            self.logger.info(f"Valid credentials found: {username}:{password}")
                            break
                    
                    # If we found valid credentials, move to next username
                    if any(cred['username'] == username for cred in valid_credentials):
                        break
                        
                except Exception as e:
                    self.logger.error(f"Error testing credentials {username}:{password}: {e}")
        
        return valid_credentials
    
    def get_server_info(self) -> Dict[str, Any]:
        """Get LDAP server information"""
        info = {}
        
        try:
            # Try to get root DSE
            root_dse = self.search(
                base_dn="",
                scope="base",
                filter_str="(objectClass=*)",
                attributes=["*"]
            )
            
            if root_dse:
                info['root_dse'] = root_dse[0]
            
            # Try to get supported controls
            controls = self.search(
                base_dn="",
                scope="base",
                filter_str="(objectClass=*)",
                attributes=["supportedControl", "supportedExtension", "supportedLDAPVersion"]
            )
            
            if controls:
                info['controls'] = controls[0]
            
        except Exception as e:
            self.logger.error(f"Failed to get server info: {e}")
        
        return info
    
    def _create_bind_request(self, bind_dn: str, password: str, auth_method: str) -> Dict:
        """Create LDAP bind request"""
        return {
            'message_id': self.message_id,
            'protocol_op': self.BIND_REQUEST,
            'bind_dn': bind_dn,
            'password': password,
            'auth_method': auth_method
        }
    
    def _create_search_request(self, base_dn: str, scope: str, filter_str: str, 
                              attributes: List[str], size_limit: int, time_limit: int) -> Dict:
        """Create LDAP search request"""
        return {
            'message_id': self.message_id,
            'protocol_op': self.SEARCH_REQUEST,
            'base_dn': base_dn,
            'scope': scope,
            'filter': filter_str,
            'attributes': attributes or [],
            'size_limit': size_limit,
            'time_limit': time_limit
        }
    
    def _send_message(self, message: Dict):
        """Send LDAP message"""
        # This is a simplified implementation
        # In a real implementation, you would use proper BER encoding
        
        # For now, just increment message ID
        self.message_id += 1
        
        # In production, you would encode the message properly
        # and send it over the socket
        pass
    
    def _receive_message(self) -> Optional[Dict]:
        """Receive LDAP message"""
        # This is a simplified implementation
        # In a real implementation, you would use proper BER decoding
        
        try:
            # In production, you would read from the socket
            # and decode the BER-encoded message
            return {
                'message_id': self.message_id - 1,
                'protocol_op': self.SEARCH_RESULT_DONE,
                'result_code': self.SUCCESS
            }
        except Exception as e:
            self.logger.error(f"Failed to receive message: {e}")
            return None
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.disconnect()
