#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
from lib.protocols.ftp.ftp_client import FTPClientMixin
import os

class Module(Post, FTPClientMixin):
    """FTP File Upload Module"""
    
    __info__ = {
        "name": "FTP Upload File",
        "description": "Uploads a local file to the FTP server",
        "author": "KittySploit Team",
        "session_type": SessionType.FTP,
    }
    
    local_file = OptFile("", "Local file path to upload", True)
    remote_path = OptString(".", "Remote directory path to upload file", False)
    remote_filename = OptString("", "Remote filename (default: same as local filename)", False)
    overwrite = OptBool(True, "Overwrite file if it already exists", False)
    
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
        
        # Check if local file exists
        if not os.path.exists(self.local_file):
            print_error(f"Local file not found: {self.local_file}")
            return False
        
        # Try to get FTP connection to verify it works
        try:
            self.open_ftp()
            return True
        except Exception as e:
            print_error(f"FTP connection error: {e}")
            return False
    
    def _check_file_exists(self, remote_path: str) -> bool:
        """Check if remote file exists"""
        try:
            connection = self.open_ftp()
            # Try to get file size - if it succeeds, file exists
            try:
                size = connection.size(remote_path)
                return size is not None
            except:
                # Try listing directory to check
                dir_path = os.path.dirname(remote_path) if '/' in remote_path else '.'
                filename = os.path.basename(remote_path) if '/' in remote_path else remote_path
                files = self.list_files(dir_path)
                for file_info in files:
                    if file_info.get('name') == filename:
                        return True
                return False
        except:
            return False
    
    def run(self):
        """Run the file upload"""
        try:
            print_info("=" * 70)
            print_info("FTP File Upload")
            print_info("=" * 70)
            
            # Get connection info
            conn_info = self.get_ftp_connection_info()
            print_info(f"FTP Server: {conn_info.get('host', 'unknown')}:{conn_info.get('port', 21)}")
            print_info(f"Username: {conn_info.get('username', 'unknown')}")
            print_info("")
            
            # Get local file info
            local_file_path = os.path.abspath(self.local_file)
            local_filename = os.path.basename(local_file_path)
            local_size = os.path.getsize(local_file_path)
            
            print_info(f"Local File: {local_file_path}")
            print_info(f"File Size: {self._format_bytes(local_size)}")
            print_info("")
            
            # Determine remote filename
            if self.remote_filename:
                remote_filename = self.remote_filename
            else:
                remote_filename = local_filename
            
            # Build remote path
            if self.remote_path and self.remote_path != ".":
                remote_file = f"{self.remote_path}/{remote_filename}".replace("//", "/")
            else:
                remote_file = remote_filename
            
            print_info(f"Remote Path: {remote_file}")
            print_info("")
            
            # Check if file exists
            if self._check_file_exists(remote_file):
                if not self.overwrite:
                    print_error(f"File already exists: {remote_file}")
                    print_info("Set overwrite=True to overwrite existing file")
                    return False
                else:
                    print_warning(f"File {remote_file} already exists, will overwrite...")
            
            # Change to target directory if specified
            if self.remote_path and self.remote_path != ".":
                try:
                    self.change_directory(self.remote_path)
                    print_info(f"Changed to directory: {self.remote_path}")
                except Exception as e:
                    print_warning(f"Could not change to {self.remote_path}: {e}")
                    print_info("Uploading to current directory instead...")
            
            # Upload file
            print_status("Uploading file...")
            try:
                connection = self.open_ftp()
                # Ensure binary mode
                try:
                    connection.voidcmd('TYPE I')  # Binary mode
                except:
                    pass
                
                self.upload_file(local_file_path, remote_file)
                
                # Verify upload
                try:
                    remote_size = self.get_file_size(remote_file)
                    if remote_size > 0:
                        print_success(f"File uploaded successfully!")
                        print_info(f"Remote file size: {self._format_bytes(remote_size)}")
                        if remote_size != local_size:
                            print_warning(f"Size mismatch: local={local_size}, remote={remote_size}")
                    else:
                        print_success(f"File uploaded (size verification unavailable)")
                except:
                    print_success(f"File uploaded successfully!")
                
                print_info("")
                print_info("-" * 70)
                print_success(f"Upload complete: {remote_file}")
                
                return True
                
            except Exception as e:
                print_error(f"Upload failed: {e}")
                raise ProcedureError(FailureType.Unknown, f"Error uploading file: {e}")
            
        except ProcedureError:
            raise
        except Exception as e:
            raise ProcedureError(FailureType.Unknown, f"Error uploading file: {e}")
    
    def _format_bytes(self, bytes_value: int) -> str:
        """Format bytes to human-readable format"""
        if bytes_value == 0:
            return "0 B"
        
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if bytes_value < 1024.0:
                return f"{bytes_value:.2f} {unit}"
            bytes_value /= 1024.0
        return f"{bytes_value:.2f} PB"
