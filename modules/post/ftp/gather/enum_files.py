#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
from lib.protocols.ftp.ftp_client import FTPClient
import os

class Module(Post, FTPClient):
    """FTP File Enumeration Module"""
    
    __info__ = {
        "name": "FTP Gather File Listing",
        "description": "Enumerates files and directories on FTP server, optionally downloading interesting files",
        "author": "KittySploit Team",
        "session_type": SessionType.FTP,
    }
    
    remote_path = OptString(".", "Remote directory path to enumerate", False)
    download_files = OptBool(False, "Download interesting files automatically", False)
    file_extensions = OptString("txt,conf,config,ini,log,sh,bat,php,jsp,asp,aspx,py,pl,key,pem,crt,db,sql", "File extensions to download (comma-separated)", False)
    max_depth = OptInteger(3, "Maximum directory depth to recurse", False)
    output_dir = OptString("/output", "Local directory to save downloaded files", False)
    
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
            self.get_ftp_connection()
            return True
        except Exception as e:
            print_error(f"FTP connection error: {e}")
            return False
    
    def _format_size(self, size_str: str) -> str:
        """Format file size for display"""
        try:
            size = int(size_str)
            for unit in ['B', 'KB', 'MB', 'GB']:
                if size < 1024.0:
                    return f"{size:.2f} {unit}"
                size /= 1024.0
            return f"{size:.2f} TB"
        except:
            return size_str
    
    def _is_interesting_file(self, filename: str) -> bool:
        """Check if file has interesting extension"""
        if not self.download_files:
            return False
        
        ext = os.path.splitext(filename)[1].lstrip('.')
        interesting_exts = [e.strip().lower() for e in self.file_extensions.split(',')]
        return ext.lower() in interesting_exts
    
    def _enumerate_directory(self, path: str, depth: int = 0, prefix: str = "") -> int:
        """
        Recursively enumerate directory
        
        Returns:
            int: Number of files found
        """
        if depth > self.max_depth:
            return 0
        
        try:
            files = self.list_files(path)
            file_count = 0
            
            for file_info in files:
                name = file_info.get('name', '')
                file_type = file_info.get('type', 'unknown')
                size = file_info.get('size', '0')
                date = file_info.get('date', '')
                perms = file_info.get('permissions', '')
                
                # Skip . and ..
                if name in ['.', '..']:
                    continue
                
                # Display file info
                size_str = self._format_size(size) if file_type == 'file' else ""
                print_info(f"{prefix} - {name} {size_str} {date}")
                
                if file_type == 'directory':
                    # Recurse into subdirectory
                    new_path = f"{path}/{name}".replace("//", "/")
                    if path == ".":
                        new_path = name
                    file_count += self._enumerate_directory(new_path, depth + 1, prefix + "  ")
                else:
                    file_count += 1
                    
                    # Download interesting files
                    if self._is_interesting_file(name):
                        try:
                            remote_file = f"{path}/{name}".replace("//", "/")
                            if path == ".":
                                remote_file = name
                            
                            # Create output directory structure
                            local_dir = os.path.join(self.output_dir, path.lstrip('./'))
                            os.makedirs(local_dir, exist_ok=True)
                            local_file = os.path.join(local_dir, name)
                            
                            self.download_file(remote_file, local_file)
                            print_success(f"Downloaded: {local_file}")
                        except Exception as e:
                            print_error(f"Failed to download {name}: {e}")
            
            return file_count
            
        except ProcedureError as e:
            print_error(f"Error accessing {path}: {e}")
            return 0
        except Exception as e:
            print_error(f"Error enumerating {path}: {e}")
            return 0
    
    def run(self):
        """Run the file enumeration"""
        try:
            # Get connection info
            conn_info = self.get_connection_info()
            print_info(f"FTP Server: {conn_info.get('host', 'unknown')}:{conn_info.get('port', 21)}")
            print_info(f"Username: {conn_info.get('username', 'unknown')}")
            print_info(f"Target Path: {self.remote_path}")
            print_info()
            
            # Get current directory
            try:
                current_dir = self.get_current_directory()
                print_info(f"Current Directory: {current_dir}")
            except:
                print_error("Could not get current directory")
            
            # Change to target directory if specified
            if self.remote_path and self.remote_path != ".":
                try:
                    self.change_directory(self.remote_path)
                    print_info(f"Changed to: {self.remote_path}")
                except Exception as e:
                    print_error(f"Could not change to {self.remote_path}: {e}")
                    print_info("Enumerating current directory instead...")
            
            # Create output directory if downloading
            if self.download_files:
                os.makedirs(self.output_dir, exist_ok=True)
                print_info(f"Download directory: {self.output_dir}")
                print_info()
            
            # Enumerate files
            print_status("File Listing:")
            file_count = self._enumerate_directory(self.remote_path)
            
            print_info()
            print_success(f"Enumeration complete. Found {file_count} files.")
            
            if self.download_files:
                print_status(f"Downloaded files saved to: {self.output_dir}")
            
            return True
            
        except ProcedureError:
            raise
        except Exception as e:
            raise ProcedureError(FailureType.Unknown, f"Error enumerating files: {e}")

