#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
from lib.protocols.ftp.ftp_client import FTPClientMixin
import os
import time

class Module(Post, FTPClientMixin):
    """FTP Download All Module"""
    
    __info__ = {
        "name": "FTP Download Directory",
        "description": "Downloads entire directory structure from FTP server recursively",
        "author": "KittySploit Team",
        "session_type": SessionType.FTP,
    }
    
    remote_path = OptString(".", "Remote directory path to download", False)
    local_path = OptString("./ftp_downloads", "Local directory to save files", True)
    max_depth = OptInteger(10, "Maximum directory depth to recurse", False)
    skip_extensions = OptString("tmp,log,cache", "File extensions to skip (comma-separated)", False)
    
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
    
    def _should_skip_file(self, filename: str) -> bool:
        """Check if file should be skipped"""
        ext = os.path.splitext(filename)[1].lstrip('.')
        skip_exts = [e.strip().lower() for e in self.skip_extensions.split(',')]
        return ext.lower() in skip_exts
    
    def _download_directory(self, remote_dir: str, local_dir: str, depth: int = 0) -> tuple:
        """
        Recursively download directory
        
        Returns:
            tuple: (files_downloaded, directories_created, total_size)
        """
        if depth > self.max_depth:
            return (0, 0, 0)
        
        files_downloaded = 0
        directories_created = 0
        total_size = 0
        
        try:
            # List files in remote directory
            files = self.list_files(remote_dir)
            
            # Create local directory
            os.makedirs(local_dir, exist_ok=True)
            if os.path.exists(local_dir):
                directories_created += 1
            
            for file_info in files:
                name = file_info.get('name', '')
                file_type = file_info.get('type', 'unknown')
                
                # Skip . and ..
                if name in ['.', '..']:
                    continue
                
                remote_path = f"{remote_dir}/{name}".replace("//", "/")
                if remote_dir == ".":
                    remote_path = name
                
                local_path = os.path.join(local_dir, name)
                
                if file_type == 'directory':
                    # Recurse into subdirectory
                    sub_files, sub_dirs, sub_size = self._download_directory(
                        remote_path, local_path, depth + 1
                    )
                    files_downloaded += sub_files
                    directories_created += sub_dirs
                    total_size += sub_size
                    print_info(f"  📁 {remote_path} -> {local_path} ({sub_files} files)")
                else:
                    # Download file
                    if self._should_skip_file(name):
                        print_warning(f"  ⏭️  Skipping {remote_path} (extension in skip list)")
                        continue
                    
                    try:
                        self.download_file(remote_path, local_path)
                        file_size = os.path.getsize(local_path) if os.path.exists(local_path) else 0
                        total_size += file_size
                        files_downloaded += 1
                        size_str = self._format_bytes(file_size)
                        print_success(f"  📄 {remote_path} -> {local_path} ({size_str})")
                    except Exception as e:
                        print_warning(f"  ❌ Failed to download {remote_path}: {e}")
            
            return (files_downloaded, directories_created, total_size)
            
        except ProcedureError as e:
            print_warning(f"Error accessing {remote_dir}: {e}")
            return (0, 0, 0)
        except Exception as e:
            print_warning(f"Error downloading {remote_dir}: {e}")
            return (0, 0, 0)
    
    def _format_bytes(self, bytes_value: int) -> str:
        """Format bytes to human-readable format"""
        if bytes_value == 0:
            return "0 B"
        
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if bytes_value < 1024.0:
                return f"{bytes_value:.2f} {unit}"
            bytes_value /= 1024.0
        return f"{bytes_value:.2f} PB"
    
    def run(self):
        """Run the download operation"""
        try:
            print_info("=" * 70)
            print_info("FTP Directory Download")
            print_info("=" * 70)
            
            # Get connection info
            conn_info = self.get_ftp_connection_info()
            print_info(f"FTP Server: {conn_info.get('host', 'unknown')}:{conn_info.get('port', 21)}")
            print_info(f"Username: {conn_info.get('username', 'unknown')}")
            print_info(f"Remote Path: {self.remote_path}")
            print_info(f"Local Path: {self.local_path}")
            print_info(f"Max Depth: {self.max_depth}")
            print_info("")
            
            # Change to target directory if specified
            if self.remote_path and self.remote_path != ".":
                try:
                    self.change_directory(self.remote_path)
                    print_info(f"Changed to remote directory: {self.remote_path}")
                except Exception as e:
                    print_warning(f"Could not change to {self.remote_path}: {e}")
                    print_info("Downloading from current directory instead...")
            
            # Create base local directory
            os.makedirs(self.local_path, exist_ok=True)
            
            # Start download
            print_info("Starting download...")
            print_info("-" * 70)
            
            start_time = time.time()
            files_downloaded, directories_created, total_size = self._download_directory(
                self.remote_path, self.local_path
            )
            elapsed_time = time.time() - start_time
            
            print_info("")
            print_info("-" * 70)
            print_success("Download complete!")
            print_info(f"Files downloaded: {files_downloaded}")
            print_info(f"Directories created: {directories_created}")
            print_info(f"Total size: {self._format_bytes(total_size)}")
            print_info(f"Time elapsed: {elapsed_time:.2f} seconds")
            print_info(f"Download location: {os.path.abspath(self.local_path)}")
            
            return True
            
        except ProcedureError:
            raise
        except Exception as e:
            raise ProcedureError(FailureType.Unknown, f"Error downloading directory: {e}")

