#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
from lib.protocols.ftp.ftp_client import FTPClientMixin
from ftplib import FTP, error_perm
import socket
import time

class Module(Post, FTPClientMixin):
    """FTP User Enumeration Module"""
    
    __info__ = {
        "name": "FTP Gather User Information",
        "description": "Enumerates FTP users, checks for anonymous access, and gathers connection information",
        "author": "KittySploit Team",
        "session_type": SessionType.FTP,
    }
    
    check_anonymous = OptBool(True, "Check for anonymous FTP access", False)
    test_common_users = OptBool(True, "Test common usernames", False)
    common_users = OptString("admin,root,ftp,user,test,guest,anonymous", "Common usernames to test (comma-separated)", False)
    
    def check(self):
        """Check if the module can run"""
        session_id_value = self.session_id.value if hasattr(self.session_id, 'value') else str(self.session_id)
        if not session_id_value:
            print_error("Session ID not set")
            return False
        
        if not self.framework or not hasattr(self.framework, 'session_manager'):
            print_error("Framework or session manager not available")
            return False
        
        session = self.framework.session_manager.get_session(session_id_value)
        if not session:
            print_error(f"Session {session_id_value} not found")
            return False
        
        # Try to get FTP connection to verify it works
        try:
            self.open_ftp()
            return True
        except Exception as e:
            print_error(f"FTP connection error: {e}")
            return False
    
    def _test_anonymous_access(self, host: str, port: int) -> dict:
        """Test anonymous FTP access"""
        result = {
            'enabled': False,
            'writable': False,
            'readable': False,
            'message': ''
        }
        
        try:
            ftp = FTP()
            ftp.connect(host, port, timeout=5)
            ftp.login('anonymous', 'anonymous@')
            
            result['enabled'] = True
            result['message'] = ftp.getwelcome()
            
            # Check if we can read
            try:
                ftp.retrlines('LIST')
                result['readable'] = True
            except:
                pass
            
            # Check if we can write
            try:
                test_file = '.test_write_access'
                ftp.storbinary(f'STOR {test_file}', b'test')
                ftp.delete(test_file)
                result['writable'] = True
            except:
                pass
            
            ftp.quit()
            
        except error_perm:
            result['enabled'] = False
            result['message'] = "Anonymous access denied"
        except Exception as e:
            result['message'] = f"Error: {e}"
        
        return result
    
    def _test_user_login(self, host: str, port: int, username: str, password: str = "") -> bool:
        """Test if a username/password combination works"""
        try:
            ftp = FTP()
            ftp.connect(host, port, timeout=5)
            ftp.login(username, password)
            ftp.quit()
            return True
        except:
            return False
    
    def _get_ftp_banner(self, host: str, port: int) -> str:
        """Get FTP server banner"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((host, port))
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            sock.close()
            return banner
        except:
            return "Could not retrieve banner"
    
    def _get_current_user_info(self) -> dict:
        """Get information about current FTP user"""
        info = {}
        
        try:
            connection = self.open_ftp()
            if connection:
                # Get current directory
                try:
                    info['current_directory'] = connection.pwd()
                except:
                    info['current_directory'] = "Unknown"
                
                # Try to get system info
                try:
                    info['system'] = connection.sendcmd('SYST')
                except:
                    info['system'] = "Unknown"
                
                # Try to get features
                try:
                    features = connection.sendcmd('FEAT')
                    info['features'] = features.split('\n')[1:] if '\n' in features else [features]
                except:
                    info['features'] = []
                
                # Check permissions by trying common operations
                info['can_list'] = False
                info['can_read'] = False
                info['can_write'] = False
                info['can_delete'] = False
                
                try:
                    connection.retrlines('LIST')
                    info['can_list'] = True
                except:
                    pass
                
                try:
                    # Try to read a file (test with pwd or similar)
                    connection.pwd()
                    info['can_read'] = True
                except:
                    pass
                
                try:
                    # Try to create a test file
                    test_file = '.test_write_' + str(int(time.time()))
                    connection.storbinary(f'STOR {test_file}', b'test')
                    connection.delete(test_file)
                    info['can_write'] = True
                    info['can_delete'] = True
                except:
                    pass
        
        except Exception as e:
            info['error'] = str(e)
        
        return info
    
    def run(self):
        """Run the user enumeration"""
        try:
            print_status("FTP User Enumeration")

            # Get connection info
            conn_info = self.get_ftp_connection_info()
            host = conn_info.get('host', 'localhost')
            port = conn_info.get('port', 21)
            current_user = conn_info.get('username', 'unknown')
            
            print_status(f"FTP Server: {host}:{port}")
            print_status(f"Current User: {current_user}")
            print_info()
            
            # Get FTP banner
            print_status("FTP Server Information:")
            banner = self._get_ftp_banner(host, port)
            print_status(f"Banner: {banner}")
            print_info()
            
            # Get current user information
            print_status("Current User Information:")
            user_info = self._get_current_user_info()
            
            if 'current_directory' in user_info:
                print_status(f"Current Directory: {user_info['current_directory']}")
            
            if 'system' in user_info:
                print_status(f"System Type: {user_info['system']}")

            if 'features' in user_info and user_info['features']:
                print_status("Server Features:")
                for feature in user_info['features'][:10]:  # Limit to first 10
                    if feature.strip():
                        print_status(f"  - {feature.strip()}")
            
            print_status("Permissions:")
            if 'can_list' in user_info:
                status = "✓" if user_info['can_list'] else "✗"
                print_status(f"  {status} List directories")
            if 'can_read' in user_info:
                status = "✓" if user_info['can_read'] else "✗"
                print_status(f"  {status} Read files")
            if 'can_write' in user_info:
                status = "✓" if user_info['can_write'] else "✗"
                print_status(f"  {status} Write files")
            if 'can_delete' in user_info:
                status = "✓" if user_info['can_delete'] else "✗"
                print_status(f"  {status} Delete files")
            
            print_info()
            
            # Test anonymous access
            if self.check_anonymous:
                print_status("Anonymous Access Test:")
                anon_result = self._test_anonymous_access(host, port)
                
                if anon_result['enabled']:
                    print_success("Anonymous FTP access is ENABLED!")
                    print_status(f"Welcome message: {anon_result['message']}")
                    if anon_result['readable']:
                        print_status("  - Anonymous users can READ files")
                    if anon_result['writable']:
                        print_success("  - Anonymous users can WRITE files (CRITICAL!)")
                else:
                    print_error("Anonymous FTP access is disabled")
                    print_status(f"Response: {anon_result['message']}")
                
                print_info()
            
            # Test common usernames
            if self.test_common_users:
                print_status("Common Username Testing:")
                print_status("Testing common usernames (passwordless)...")
                
                common_users_list = [u.strip() for u in self.common_users.split(',')]
                found_users = []
                
                for username in common_users_list:
                    if username.lower() == current_user.lower():
                        continue  # Skip current user
                    
                    if self._test_user_login(host, port, username, ""):
                        found_users.append(username)
                        print_success(f"{username} - Passwordless login works!")
                    else:
                        print_info(f"{username}")
                
                if found_users:
                    print_success(f"Found {len(found_users)} users with passwordless access!")
                else:
                    print_error("No passwordless logins found for common usernames")
                
                print_info()
            
            print_status("Enumeration complete!")
            
            return True
            
        except ProcedureError:
            raise
        except Exception as e:
            raise ProcedureError(FailureType.Unknown, f"Error enumerating users: {e}")

