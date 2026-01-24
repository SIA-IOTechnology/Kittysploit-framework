#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
from lib.protocols.ftp.ftp_client import FTPClientMixin
import os
import re

class Module(Post, FTPClientMixin):
    """FTP File Search Module"""
    
    __info__ = {
        "name": "FTP Search Files",
        "description": "Searches for files on FTP server by name pattern, extension, or content keywords",
        "author": "KittySploit Team",
        "session_type": SessionType.FTP,
    }
    
    search_path = OptString(".", "Remote directory path to search", False)
    search_pattern = OptString("", "File name pattern to search (supports wildcards: *, ?)", True)
    file_extensions = OptString("", "File extensions to search (comma-separated, e.g., txt,php,conf)", False)
    keywords = OptString("", "Keywords to search in file names (comma-separated)", False)
    max_depth = OptInteger(10, "Maximum directory depth to recurse", False)
    max_size = OptInteger(10485760, "Maximum file size to search (bytes, 0 = no limit)", False)
    download_matches = OptBool(False, "Download matching files", False)
    output_dir = OptString("./search_results", "Local directory to save downloaded files", False)
    
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
    
    def _matches_pattern(self, filename: str, pattern: str) -> bool:
        """Check if filename matches pattern (supports * and ? wildcards)"""
        if not pattern:
            return True
        
        # Convert wildcard pattern to regex
        regex_pattern = pattern.replace('.', r'\.')
        regex_pattern = regex_pattern.replace('*', '.*')
        regex_pattern = regex_pattern.replace('?', '.')
        regex_pattern = f'^{regex_pattern}$'
        
        try:
            return bool(re.match(regex_pattern, filename, re.IGNORECASE))
        except:
            return False
    
    def _matches_extensions(self, filename: str) -> bool:
        """Check if file has matching extension"""
        if not self.file_extensions:
            return True
        
        ext = os.path.splitext(filename)[1].lstrip('.').lower()
        search_exts = [e.strip().lower() for e in self.file_extensions.split(',')]
        return ext in search_exts
    
    def _matches_keywords(self, filename: str) -> bool:
        """Check if filename contains any keywords"""
        if not self.keywords:
            return True
        
        filename_lower = filename.lower()
        search_keywords = [k.strip().lower() for k in self.keywords.split(',')]
        return any(keyword in filename_lower for keyword in search_keywords)
    
    def _matches_criteria(self, filename: str, file_info: dict) -> bool:
        """Check if file matches all search criteria"""
        # Check pattern
        if self.search_pattern and not self._matches_pattern(filename, self.search_pattern):
            return False
        
        # Check extensions
        if not self._matches_extensions(filename):
            return False
        
        # Check keywords
        if not self._matches_keywords(filename):
            return False
        
        # Check file size
        if self.max_size > 0:
            try:
                file_size = int(file_info.get('size', 0))
                if file_size > self.max_size:
                    return False
            except:
                pass
        
        return True
    
    def _search_files(self, path: str, depth: int = 0, found_files: list = None) -> list:
        """Recursively search for files matching criteria"""
        if found_files is None:
            found_files = []
        
        if depth > self.max_depth:
            return found_files
        
        try:
            files = self.list_files(path)
            
            for file_info in files:
                name = file_info.get('name', '')
                file_type = file_info.get('type', 'unknown')
                
                # Skip . and ..
                if name in ['.', '..']:
                    continue
                
                remote_file = f"{path}/{name}".replace("//", "/")
                if path == ".":
                    remote_file = name
                
                if file_type == 'directory':
                    # Recurse into subdirectory
                    self._search_files(remote_file, depth + 1, found_files)
                else:
                    # Check if file matches criteria
                    if self._matches_criteria(name, file_info):
                        found_files.append({
                            'path': remote_file,
                            'name': name,
                            'size': file_info.get('size', '0'),
                            'date': file_info.get('date', '')
                        })
                        print_success(f"  ✓ Found: {remote_file}")
            
            return found_files
            
        except ProcedureError as e:
            print_warning(f"Error accessing {path}: {e}")
            return found_files
        except Exception as e:
            print_warning(f"Error searching {path}: {e}")
            return found_files
    
    def _download_file(self, remote_path: str, local_path: str) -> bool:
        """Download a file"""
        try:
            # Create directory if needed
            local_dir = os.path.dirname(local_path)
            if local_dir:
                os.makedirs(local_dir, exist_ok=True)
            
            self.download_file(remote_path, local_path)
            return True
        except Exception as e:
            print_warning(f"Failed to download {remote_path}: {e}")
            return False
    
    def _format_bytes(self, bytes_value: int) -> str:
        """Format bytes to human-readable format"""
        try:
            size = int(bytes_value)
            if size == 0:
                return "0 B"
            
            for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
                if size < 1024.0:
                    return f"{size:.2f} {unit}"
                size /= 1024.0
            return f"{size:.2f} PB"
        except:
            return str(bytes_value)
    
    def run(self):
        """Run the file search"""
        try:
            print_info("=" * 70)
            print_info("FTP File Search")
            print_info("=" * 70)
            
            # Get connection info
            conn_info = self.get_ftp_connection_info()
            print_info(f"FTP Server: {conn_info.get('host', 'unknown')}:{conn_info.get('port', 21)}")
            print_info(f"Username: {conn_info.get('username', 'unknown')}")
            print_info("")
            
            # Display search criteria
            print_status("Search Criteria:")
            if self.search_pattern:
                print_info(f"  Pattern: {self.search_pattern}")
            if self.file_extensions:
                print_info(f"  Extensions: {self.file_extensions}")
            if self.keywords:
                print_info(f"  Keywords: {self.keywords}")
            if self.max_size > 0:
                print_info(f"  Max Size: {self._format_bytes(self.max_size)}")
            print_info(f"  Search Path: {self.search_path}")
            print_info(f"  Max Depth: {self.max_depth}")
            print_info("")
            
            # Change to target directory if specified
            if self.search_path and self.search_path != ".":
                try:
                    self.change_directory(self.search_path)
                    print_info(f"Changed to directory: {self.search_path}")
                except Exception as e:
                    print_warning(f"Could not change to {self.search_path}: {e}")
                    print_info("Searching current directory instead...")
            
            # Create output directory if downloading
            if self.download_matches:
                os.makedirs(self.output_dir, exist_ok=True)
                print_info(f"Download directory: {self.output_dir}")
                print_info("")
            
            # Search for files
            print_status("Searching for files...")
            print_info("-" * 70)
            found_files = self._search_files(self.search_path)
            print_info("")
            
            if not found_files:
                print_error("No files found matching search criteria")
                return True
            
            # Display results
            print_success(f"Found {len(found_files)} file(s):")
            print_info("")
            
            total_size = 0
            for file_info in found_files:
                size_str = self._format_bytes(int(file_info.get('size', 0)))
                date_str = file_info.get('date', '')
                print_info(f"  - {file_info['path']} ({size_str}, {date_str})")
                try:
                    total_size += int(file_info.get('size', 0))
                except:
                    pass
            
            print_info("")
            print_info(f"Total size: {self._format_bytes(total_size)}")
            print_info("")
            
            # Download files if requested
            if self.download_matches and found_files:
                print_status("Downloading matching files...")
                print_info("-" * 70)
                
                downloaded = 0
                for file_info in found_files:
                    remote_path = file_info['path']
                    # Create local path preserving directory structure
                    local_rel_path = remote_path.lstrip('./')
                    local_path = os.path.join(self.output_dir, local_rel_path)
                    
                    if self._download_file(remote_path, local_path):
                        downloaded += 1
                        print_success(f"  ✓ Downloaded: {local_path}")
                
                print_info("")
                print_success(f"Downloaded {downloaded}/{len(found_files)} files")
                print_status(f"Files saved to: {os.path.abspath(self.output_dir)}")
            
            return True
            
        except ProcedureError:
            raise
        except Exception as e:
            raise ProcedureError(FailureType.Unknown, f"Error searching files: {e}")
