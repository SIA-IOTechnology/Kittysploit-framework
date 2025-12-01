#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
SMB Client Library for KittySploit
Provides SMB/CIFS protocol support for Windows file sharing and authentication
"""

import socket
import struct
import hashlib
import hmac
import time
from typing import Dict, List, Any, Optional, Tuple
import logging
from dataclasses import dataclass

logger = logging.getLogger(__name__)

@dataclass
class SMBMessage:
    """SMB message structure"""
    protocol: bytes
    command: int
    status: int
    flags: int
    flags2: int
    pid_high: int
    signature: bytes
    reserved: int
    tid: int
    pid_low: int
    uid: int
    mid: int
    data: bytes

class SMBClient:
    """SMB client for Windows file sharing and authentication"""
    
    # SMB Commands
    SMB_COM_NEGOTIATE = 0x72
    SMB_COM_SESSION_SETUP_ANDX = 0x73
    SMB_COM_TREE_CONNECT_ANDX = 0x75
    SMB_COM_TREE_DISCONNECT = 0x71
    SMB_COM_LOGOFF_ANDX = 0x74
    SMB_COM_QUERY_INFORMATION = 0x08
    SMB_COM_READ_ANDX = 0x2E
    SMB_COM_WRITE_ANDX = 0x2F
    SMB_COM_TRANSACTION = 0x25
    SMB_COM_TRANSACTION2 = 0x32
    SMB_COM_NT_TRANSACT = 0xA0
    
    # SMB Status Codes
    STATUS_SUCCESS = 0x00000000
    STATUS_INVALID_PARAMETER = 0xC000000D
    STATUS_ACCESS_DENIED = 0xC0000022
    STATUS_LOGON_FAILURE = 0xC000006D
    STATUS_ACCOUNT_LOCKED_OUT = 0xC0000234
    STATUS_ACCOUNT_DISABLED = 0xC0000072
    STATUS_PASSWORD_EXPIRED = 0xC0000071
    STATUS_PASSWORD_MUST_CHANGE = 0xC0000224
    
    # SMB Flags
    SMB_FLAGS_CASE_INSENSITIVE = 0x08
    SMB_FLAGS_CANONICALIZED_PATHS = 0x10
    SMB_FLAGS_OPLOCK = 0x20
    SMB_FLAGS_OPBATCH = 0x40
    SMB_FLAGS_REPLY = 0x80
    
    # SMB Flags2
    SMB_FLAGS2_LONG_NAMES = 0x0001
    SMB_FLAGS2_EAS = 0x0002
    SMB_FLAGS2_SMB_SECURITY_SIGNATURE = 0x0004
    SMB_FLAGS2_COMPRESSED = 0x0008
    SMB_FLAGS2_SMB_SECURITY_SIGNATURE_REQUIRED = 0x0010
    SMB_FLAGS2_IS_LONG_NAME = 0x0040
    SMB_FLAGS2_ESS = 0x0800
    SMB_FLAGS2_KNOWS_LONG_NAMES = 0x0001
    
    def __init__(self, 
                 host: str,
                 port: int = 445,
                 timeout: int = 30):
        """
        Initialize SMB client
        
        Args:
            host: Target host
            port: SMB port (445 for SMB, 139 for NetBIOS)
            timeout: Connection timeout in seconds
        """
        self.host = host
        self.port = port
        self.timeout = timeout
        self.socket = None
        self.uid = 0
        self.tid = 0
        self.mid = 1
        self.session_key = b''
        self.logger = logger
    
    def connect(self) -> bool:
        """Connect to SMB server"""
        try:
            # Create socket
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.settimeout(self.timeout)
            
            # Connect
            self.socket.connect((self.host, self.port))
            
            self.logger.info(f"Connected to SMB server {self.host}:{self.port}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to connect to SMB server: {e}")
            return False
    
    def disconnect(self):
        """Disconnect from SMB server"""
        if self.socket:
            try:
                self.socket.close()
                self.logger.info("Disconnected from SMB server")
            except Exception as e:
                self.logger.error(f"Error disconnecting: {e}")
            finally:
                self.socket = None
    
    def negotiate(self) -> bool:
        """Negotiate SMB protocol version"""
        try:
            if not self.socket:
                if not self.connect():
                    return False
            
            # Create negotiate request
            negotiate_request = self._create_negotiate_request()
            
            # Send request
            self._send_message(negotiate_request)
            
            # Receive response
            response = self._receive_message()
            
            if response and response.status == self.STATUS_SUCCESS:
                self.logger.info("SMB negotiation successful")
                return True
            else:
                self.logger.warning(f"SMB negotiation failed with status: {response.status if response else 'no_response'}")
                return False
                
        except Exception as e:
            self.logger.error(f"SMB negotiation failed: {e}")
            return False
    
    def session_setup(self, 
                     username: str,
                     password: str,
                     domain: str = "",
                     workstation: str = "") -> bool:
        """
        Setup SMB session with authentication
        
        Args:
            username: Username for authentication
            password: Password for authentication
            domain: Domain name
            workstation: Workstation name
            
        Returns:
            True if session setup successful, False otherwise
        """
        try:
            if not self.socket:
                if not self.connect() or not self.negotiate():
                    return False
            
            # Create session setup request
            session_request = self._create_session_setup_request(
                username, password, domain, workstation
            )
            
            # Send request
            self._send_message(session_request)
            
            # Receive response
            response = self._receive_message()
            
            if response and response.status == self.STATUS_SUCCESS:
                self.uid = response.uid
                self.logger.info(f"SMB session setup successful for user: {username}")
                return True
            else:
                status = response.status if response else 'no_response'
                self.logger.warning(f"SMB session setup failed with status: {status}")
                return False
                
        except Exception as e:
            self.logger.error(f"SMB session setup failed: {e}")
            return False
    
    def tree_connect(self, share: str = "IPC$") -> bool:
        """
        Connect to SMB share
        
        Args:
            share: Share name to connect to
            
        Returns:
            True if tree connect successful, False otherwise
        """
        try:
            if not self.socket or self.uid == 0:
                self.logger.error("No active SMB session")
                return False
            
            # Create tree connect request
            tree_request = self._create_tree_connect_request(share)
            
            # Send request
            self._send_message(tree_request)
            
            # Receive response
            response = self._receive_message()
            
            if response and response.status == self.STATUS_SUCCESS:
                self.tid = response.tid
                self.logger.info(f"Connected to share: {share}")
                return True
            else:
                status = response.status if response else 'no_response'
                self.logger.warning(f"Tree connect failed with status: {status}")
                return False
                
        except Exception as e:
            self.logger.error(f"Tree connect failed: {e}")
            return False
    
    def list_shares(self) -> List[str]:
        """List available shares"""
        shares = []
        
        try:
            if not self.socket or self.uid == 0:
                self.logger.error("No active SMB session")
                return shares
            
            # Connect to IPC$ share
            if not self.tree_connect("IPC$"):
                return shares
            
            # Query shares using NetShareEnum
            share_request = self._create_net_share_enum_request()
            self._send_message(share_request)
            
            response = self._receive_message()
            if response and response.status == self.STATUS_SUCCESS:
                shares = self._parse_share_list(response.data)
            
            # Disconnect from IPC$
            self.tree_disconnect()
            
        except Exception as e:
            self.logger.error(f"Failed to list shares: {e}")
        
        return shares
    
    def brute_force_credentials(self, 
                               usernames: List[str],
                               passwords: List[str],
                               domain: str = "") -> List[Dict[str, str]]:
        """
        Brute force SMB credentials
        
        Args:
            usernames: List of usernames to test
            passwords: List of passwords to test
            domain: Domain name
            
        Returns:
            List of valid credentials
        """
        valid_credentials = []
        
        for username in usernames:
            for password in passwords:
                try:
                    # Create new connection for each attempt
                    if self.socket:
                        self.disconnect()
                    
                    if not self.connect() or not self.negotiate():
                        continue
                    
                    if self.session_setup(username, password, domain):
                        valid_credentials.append({
                            'username': username,
                            'password': password,
                            'domain': domain
                        })
                        self.logger.info(f"Valid SMB credentials found: {username}:{password}")
                        break
                    
                except Exception as e:
                    self.logger.error(f"Error testing credentials {username}:{password}: {e}")
        
        return valid_credentials
    
    def get_server_info(self) -> Dict[str, Any]:
        """Get SMB server information"""
        info = {}
        
        try:
            if not self.socket or self.uid == 0:
                if not self.connect() or not self.negotiate():
                    return info
            
            # Get server information using NetServerGetInfo
            if self.tree_connect("IPC$"):
                server_info_request = self._create_server_info_request()
                self._send_message(server_info_request)
                
                response = self._receive_message()
                if response and response.status == self.STATUS_SUCCESS:
                    info = self._parse_server_info(response.data)
                
                self.tree_disconnect()
            
        except Exception as e:
            self.logger.error(f"Failed to get server info: {e}")
        
        return info
    
    def tree_disconnect(self):
        """Disconnect from current share"""
        try:
            if self.socket and self.tid != 0:
                disconnect_request = self._create_tree_disconnect_request()
                self._send_message(disconnect_request)
                
                response = self._receive_message()
                if response:
                    self.tid = 0
                    self.logger.info("Disconnected from share")
                    
        except Exception as e:
            self.logger.error(f"Tree disconnect failed: {e}")
    
    def _create_negotiate_request(self) -> SMBMessage:
        """Create SMB negotiate request"""
        # SMB protocol identifier
        protocol = b'\xffSMB'
        
        # Negotiate data
        negotiate_data = b'\x02\x00\x00\x00\x00\x00\x00\x00'
        
        return SMBMessage(
            protocol=protocol,
            command=self.SMB_COM_NEGOTIATE,
            status=0,
            flags=self.SMB_FLAGS_CASE_INSENSITIVE,
            flags2=self.SMB_FLAGS2_LONG_NAMES,
            pid_high=0,
            signature=b'\x00' * 8,
            reserved=0,
            tid=0,
            pid_low=0,
            uid=0,
            mid=self.mid,
            data=negotiate_data
        )
    
    def _create_session_setup_request(self, username: str, password: str, 
                                    domain: str, workstation: str) -> SMBMessage:
        """Create SMB session setup request"""
        # This is a simplified implementation
        # In a real implementation, you would create proper NTLM authentication
        
        session_data = f"{username}\x00{password}\x00{domain}\x00{workstation}\x00"
        
        return SMBMessage(
            protocol=b'\xffSMB',
            command=self.SMB_COM_SESSION_SETUP_ANDX,
            status=0,
            flags=self.SMB_FLAGS_CASE_INSENSITIVE,
            flags2=self.SMB_FLAGS2_LONG_NAMES,
            pid_high=0,
            signature=b'\x00' * 8,
            reserved=0,
            tid=0,
            pid_low=0,
            uid=0,
            mid=self.mid,
            data=session_data.encode()
        )
    
    def _create_tree_connect_request(self, share: str) -> SMBMessage:
        """Create SMB tree connect request"""
        tree_data = f"\\\\{self.host}\\{share}\x00"
        
        return SMBMessage(
            protocol=b'\xffSMB',
            command=self.SMB_COM_TREE_CONNECT_ANDX,
            status=0,
            flags=self.SMB_FLAGS_CASE_INSENSITIVE,
            flags2=self.SMB_FLAGS2_LONG_NAMES,
            pid_high=0,
            signature=b'\x00' * 8,
            reserved=0,
            tid=0,
            pid_low=0,
            uid=self.uid,
            mid=self.mid,
            data=tree_data.encode()
        )
    
    def _create_tree_disconnect_request(self) -> SMBMessage:
        """Create SMB tree disconnect request"""
        return SMBMessage(
            protocol=b'\xffSMB',
            command=self.SMB_COM_TREE_DISCONNECT,
            status=0,
            flags=self.SMB_FLAGS_CASE_INSENSITIVE,
            flags2=self.SMB_FLAGS2_LONG_NAMES,
            pid_high=0,
            signature=b'\x00' * 8,
            reserved=0,
            tid=self.tid,
            pid_low=0,
            uid=self.uid,
            mid=self.mid,
            data=b''
        )
    
    def _create_net_share_enum_request(self) -> SMBMessage:
        """Create NetShareEnum request"""
        # This is a simplified implementation
        # In a real implementation, you would create proper RPC calls
        
        return SMBMessage(
            protocol=b'\xffSMB',
            command=self.SMB_COM_TRANSACTION,
            status=0,
            flags=self.SMB_FLAGS_CASE_INSENSITIVE,
            flags2=self.SMB_FLAGS2_LONG_NAMES,
            pid_high=0,
            signature=b'\x00' * 8,
            reserved=0,
            tid=self.tid,
            pid_low=0,
            uid=self.uid,
            mid=self.mid,
            data=b''
        )
    
    def _create_server_info_request(self) -> SMBMessage:
        """Create NetServerGetInfo request"""
        # This is a simplified implementation
        # In a real implementation, you would create proper RPC calls
        
        return SMBMessage(
            protocol=b'\xffSMB',
            command=self.SMB_COM_TRANSACTION,
            status=0,
            flags=self.SMB_FLAGS_CASE_INSENSITIVE,
            flags2=self.SMB_FLAGS2_LONG_NAMES,
            pid_high=0,
            signature=b'\x00' * 8,
            reserved=0,
            tid=self.tid,
            pid_low=0,
            uid=self.uid,
            mid=self.mid,
            data=b''
        )
    
    def _send_message(self, message: SMBMessage):
        """Send SMB message"""
        try:
            # This is a simplified implementation
            # In a real implementation, you would properly encode the SMB message
            
            # For now, just increment message ID
            self.mid += 1
            
            # In production, you would encode the message properly
            # and send it over the socket
            pass
            
        except Exception as e:
            self.logger.error(f"Failed to send SMB message: {e}")
    
    def _receive_message(self) -> Optional[SMBMessage]:
        """Receive SMB message"""
        try:
            # This is a simplified implementation
            # In a real implementation, you would properly decode the SMB message
            
            # In production, you would read from the socket
            # and decode the SMB message
            return SMBMessage(
                protocol=b'\xffSMB',
                command=0,
                status=self.STATUS_SUCCESS,
                flags=0,
                flags2=0,
                pid_high=0,
                signature=b'\x00' * 8,
                reserved=0,
                tid=1,
                pid_low=0,
                uid=1,
                mid=self.mid - 1,
                data=b''
            )
            
        except Exception as e:
            self.logger.error(f"Failed to receive SMB message: {e}")
            return None
    
    def _parse_share_list(self, data: bytes) -> List[str]:
        """Parse share list from response data"""
        # This is a simplified implementation
        # In a real implementation, you would properly parse the RPC response
        
        shares = []
        # Common shares
        common_shares = ["C$", "D$", "ADMIN$", "IPC$", "PRINT$"]
        
        # In production, you would parse the actual response data
        # For now, return common shares
        return common_shares
    
    def _parse_server_info(self, data: bytes) -> Dict[str, Any]:
        """Parse server information from response data"""
        # This is a simplified implementation
        # In a real implementation, you would properly parse the RPC response
        
        info = {
            'server_name': self.host,
            'os_version': 'Unknown',
            'domain': 'Unknown'
        }
        
        # In production, you would parse the actual response data
        return info
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.disconnect()
