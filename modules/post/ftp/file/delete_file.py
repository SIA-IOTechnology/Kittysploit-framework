#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
from lib.protocols.ftp.ftp_client import FTPClientMixin
import os

class Module(Post, FTPClientMixin):
    """FTP File Deletion Module"""
    
    __info__ = {
        "name": "FTP Delete File",
        "description": "Deletes files or directories from the FTP server",
        "author": "KittySploit Team",
        "session_type": SessionType.FTP,
    }
    
    remote_path = OptString("", "Remote file or directory path to delete", True)
    recursive = OptBool(False, "Recursively delete directories", False)
    confirm = OptBool(False, "Skip confirmation prompt", False)
    
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
    
    def _delete_directory(self, remote_path: str) -> tuple:
        """
        Recursively delete directory and its contents
        
        Returns:
            tuple: (files_deleted, directories_deleted)
        """
        files_deleted = 0
        directories_deleted = 0
        
        try:
            # List files in directory
            files = self.list_files(remote_path)
            
            for file_info in files:
                name = file_info.get('name', '')
                file_type = file_info.get('type', 'unknown')
                
                # Skip . and ..
                if name in ['.', '..']:
                    continue
                
                file_path = f"{remote_path}/{name}".replace("//", "/")
                if remote_path == ".":
                    file_path = name
                
                if file_type == 'directory':
                    if self.recursive:
                        # Recursively delete subdirectory
                        sub_files, sub_dirs = self._delete_directory(file_path)
                        files_deleted += sub_files
                        directories_deleted += sub_dirs
                        
                        # Delete the directory itself
                        try:
                            connection = self.open_ftp()
                            connection.rmd(file_path)
                            directories_deleted += 1
                            print_success(f"  ✓ Deleted directory: {file_path}")
                        except Exception as e:
                            print_warning(f"  ✗ Failed to delete directory {file_path}: {e}")
                    else:
                        print_warning(f"  ⏭️  Skipping directory (use recursive=True): {file_path}")
                else:
                    # Delete file
                    try:
                        connection = self.open_ftp()
                        connection.delete(file_path)
                        files_deleted += 1
                        print_success(f"  ✓ Deleted file: {file_path}")
                    except Exception as e:
                        print_warning(f"  ✗ Failed to delete file {file_path}: {e}")
            
            return (files_deleted, directories_deleted)
            
        except Exception as e:
            print_warning(f"Error deleting directory {remote_path}: {e}")
            return (files_deleted, directories_deleted)
    
    def _check_path_exists(self, remote_path: str) -> tuple:
        """
        Check if path exists and return its type
        
        Returns:
            tuple: (exists, is_directory)
        """
        try:
            connection = self.open_ftp()
            
            # Try to get file size (for files)
            try:
                size = connection.size(remote_path)
                if size is not None:
                    return (True, False)
            except:
                pass
            
            # Try to change to directory (for directories)
            try:
                original_dir = connection.pwd()
                connection.cwd(remote_path)
                connection.cwd(original_dir)
                return (True, True)
            except:
                pass
            
            # Try listing parent directory
            if '/' in remote_path:
                parent_dir = '/'.join(remote_path.split('/')[:-1])
                filename = remote_path.split('/')[-1]
            else:
                parent_dir = '.'
                filename = remote_path
            
            files = self.list_files(parent_dir)
            for file_info in files:
                if file_info.get('name') == filename:
                    is_dir = file_info.get('type') == 'directory'
                    return (True, is_dir)
            
            return (False, False)
            
        except:
            return (False, False)
    
    def run(self):
        """Run the file deletion"""
        try:
            print_info("=" * 70)
            print_info("FTP File Deletion")
            print_info("=" * 70)
            
            # Get connection info
            conn_info = self.get_ftp_connection_info()
            print_info(f"FTP Server: {conn_info.get('host', 'unknown')}:{conn_info.get('port', 21)}")
            print_info(f"Username: {conn_info.get('username', 'unknown')}")
            print_info(f"Target Path: {self.remote_path}")
            print_info(f"Recursive: {self.recursive}")
            print_info("")
            
            # Check if path exists
            exists, is_directory = self._check_path_exists(self.remote_path)
            
            if not exists:
                print_error(f"Path not found: {self.remote_path}")
                return False
            
            path_type = "directory" if is_directory else "file"
            print_info(f"Path type: {path_type}")
            
            # Confirmation
            if not self.confirm:
                print_warning("⚠️  WARNING: This will permanently delete the target!")
                print_info(f"Target: {self.remote_path}")
                print_info(f"Type: {path_type}")
                if is_directory and self.recursive:
                    print_warning("Recursive deletion is enabled - all contents will be deleted!")
                print_info("")
                response = input("Continue? (yes/no): ").strip().lower()
                if response not in ['yes', 'y']:
                    print_info("Deletion cancelled")
                    return False
                print_info("")
            
            # Delete
            print_status("Deleting...")
            print_info("-" * 70)
            
            connection = self.open_ftp()
            
            if is_directory:
                if self.recursive:
                    # Recursively delete directory contents
                    files_deleted, dirs_deleted = self._delete_directory(self.remote_path)
                    
                    # Delete the directory itself
                    try:
                        connection.rmd(self.remote_path)
                        dirs_deleted += 1
                        print_success(f"✓ Deleted directory: {self.remote_path}")
                    except Exception as e:
                        print_warning(f"✗ Failed to delete directory {self.remote_path}: {e}")
                    
                    print_info("")
                    print_info("-" * 70)
                    print_success(f"Deletion complete!")
                    print_info(f"Files deleted: {files_deleted}")
                    print_info(f"Directories deleted: {dirs_deleted}")
                else:
                    # Try to delete empty directory
                    try:
                        connection.rmd(self.remote_path)
                        print_success(f"✓ Deleted directory: {self.remote_path}")
                    except Exception as e:
                        print_error(f"Failed to delete directory: {e}")
                        print_info("Directory may not be empty. Use recursive=True to delete contents.")
            else:
                # Delete file
                try:
                    connection.delete(self.remote_path)
                    print_success(f"✓ Deleted file: {self.remote_path}")
                except Exception as e:
                    print_error(f"Failed to delete file: {e}")
                    raise ProcedureError(FailureType.Unknown, f"Error deleting file: {e}")
            
            return True
            
        except ProcedureError:
            raise
        except Exception as e:
            raise ProcedureError(FailureType.Unknown, f"Error deleting file: {e}")
