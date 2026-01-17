#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
from lib.protocols.http.http_client import Http_client
import re
import urllib.parse


class Module(Auxiliary, Http_client):

    __info__ = {
        'name': 'Drupal Vulnerability Scanner',
        'description': 'Scans for Drupal-specific vulnerabilities, version information, exposed files, and security misconfigurations',
        'author': 'KittySploit Team',
        'tags': ['web', 'drupal', 'scanner', 'security', 'vulnerability', 'cms'],
        'references': [
            'https://www.drupal.org/security',
            'https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword=drupal',
            'https://owasp.org/www-project-web-security-testing-guide/'
        ]
    }

    # Known Drupal CVEs
    DRUPAL_CVES = {
        'CVE-2023-47514': {
            'name': 'Remote Code Execution',
            'affected_versions': ['< 10.1.6', '< 9.5.11'],
            'severity': 'Critical',
            'description': 'Remote code execution vulnerability'
        },
        'CVE-2023-47515': {
            'name': 'Cross-Site Scripting',
            'affected_versions': ['< 10.1.6', '< 9.5.11'],
            'severity': 'Medium',
            'description': 'Cross-site scripting vulnerability'
        },
        'CVE-2023-4425': {
            'name': 'Access Bypass',
            'affected_versions': ['< 10.1.3', '< 9.5.8'],
            'severity': 'High',
            'description': 'Access bypass vulnerability'
        },
        'CVE-2023-31628': {
            'name': 'SQL Injection',
            'affected_versions': ['< 10.0.10', '< 9.5.6'],
            'severity': 'Critical',
            'description': 'SQL injection vulnerability'
        },
        'CVE-2022-2526': {
            'name': 'Remote Code Execution',
            'affected_versions': ['< 9.4.3', '< 9.3.22'],
            'severity': 'Critical',
            'description': 'Remote code execution via PEAR Archive_Tar'
        },
        'CVE-2018-7600': {
            'name': 'Drupalgeddon2 - Remote Code Execution',
            'affected_versions': ['< 7.58', '< 8.5.1'],
            'severity': 'Critical',
            'description': 'Remote code execution vulnerability (Drupalgeddon2)'
        },
        'CVE-2018-7602': {
            'name': 'Remote Code Execution',
            'affected_versions': ['< 7.58', '< 8.5.1'],
            'severity': 'Critical',
            'description': 'Remote code execution vulnerability'
        },
    }

    # Drupal-specific paths to check
    DRUPAL_PATHS = [
        '/CHANGELOG.txt',
        '/CHANGELOG.md',
        '/README.txt',
        '/README.md',
        '/sites/default/settings.php',
        '/sites/default/default.settings.php',
        '/sites/default/files',
        '/sites/all/modules',
        '/sites/all/themes',
        '/modules',
        '/themes',
        '/includes',
        '/misc',
        '/profiles',
        '/core',
        '/web.config',
        '/.htaccess',
        '/update.php',
        '/install.php',
        '/cron.php',
        '/xmlrpc.php',
        '/user',
        '/user/login',
        '/user/register',
        '/admin',
        '/node',
        '/taxonomy',
    ]

    # Sensitive files
    SENSITIVE_FILES = [
        '/sites/default/settings.php',
        '/sites/default/default.settings.php',
        '/.git/config',
        '/.git/HEAD',
        '/.env',
        '/composer.json',
        '/package.json',
    ]

    def check(self):
        """
        Check if the target is accessible and running Drupal
        """
        try:
            response = self.http_request(method="GET", path="/")
            if response:
                # Check for Drupal indicators
                content = response.text.lower()
                headers = str(response.headers).lower()
                
                drupal_indicators = [
                    'drupal', 'drupal.settings', 'drupal.js',
                    'sites/default/files', 'sites/all/modules',
                    'generator.*drupal', 'x-drupal-cache'
                ]
                
                if any(indicator in content or indicator in headers for indicator in drupal_indicators):
                    return True
                # Check for Drupal paths
                test_response = self.http_request(method="GET", path="/CHANGELOG.txt")
                if test_response and 'drupal' in test_response.text.lower():
                    return True
                # Even if not detected, continue scanning
                return True
            return False
        except Exception as e:
            return False

    def detect_drupal_version(self):
        """
        Detect Drupal version
        """
        try:
            # Try CHANGELOG.txt
            response = self.http_request(method="GET", path="/CHANGELOG.txt")
            if response and response.status_code == 200:
                # Look for version in CHANGELOG
                version_match = re.search(r'Drupal\s+([\d\.]+)', response.text, re.IGNORECASE)
                if version_match:
                    return version_match.group(1)
            
            # Try README.txt
            response = self.http_request(method="GET", path="/README.txt")
            if response and response.status_code == 200:
                version_match = re.search(r'Drupal\s+([\d\.]+)', response.text, re.IGNORECASE)
                if version_match:
                    return version_match.group(1)
            
            # Check generator meta tag
            response = self.http_request(method="GET", path="/")
            if response:
                generator_match = re.search(r'<meta\s+name=["\']generator["\']\s+content=["\']Drupal\s+([\d\.]+)', response.text, re.IGNORECASE)
                if generator_match:
                    return generator_match.group(1)
                
                # Check for Drupal in JavaScript
                drupal_js_match = re.search(r'Drupal\.settings.*version["\']?\s*:\s*["\']?([\d\.]+)', response.text, re.IGNORECASE)
                if drupal_js_match:
                    return drupal_js_match.group(1)
            
            return None
        except Exception as e:
            print_debug(f"Error detecting Drupal version: {str(e)}")
            return None

    def compare_versions(self, version1, version2):
        """
        Compare two version strings
        """
        try:
            v1_parts = [int(x) for x in version1.split('.')]
            v2_parts = [int(x) for x in version2.split('.')]
            
            max_len = max(len(v1_parts), len(v2_parts))
            v1_parts.extend([0] * (max_len - len(v1_parts)))
            v2_parts.extend([0] * (max_len - len(v2_parts)))
            
            for i in range(max_len):
                if v1_parts[i] < v2_parts[i]:
                    return -1
                elif v1_parts[i] > v2_parts[i]:
                    return 1
            return 0
        except:
            return 0

    def is_version_vulnerable(self, version, affected_versions):
        """
        Check if a version is vulnerable
        """
        if not version:
            return False
        
        for affected in affected_versions:
            if affected.startswith('< '):
                threshold = affected[2:].strip()
                if self.compare_versions(version, threshold) < 0:
                    return True
        
        return False

    def check_cves(self):
        """
        Check for known CVEs
        """
        if not self.drupal_version:
            return
        
        for cve_id, cve_info in self.DRUPAL_CVES.items():
            if self.is_version_vulnerable(self.drupal_version, cve_info['affected_versions']):
                self.vulnerabilities.append({
                    'type': 'CVE',
                    'id': cve_id,
                    'name': cve_info['name'],
                    'severity': cve_info['severity'],
                    'description': cve_info['description'],
                    'version': self.drupal_version
                })

    def check_sensitive_files(self):
        """
        Check for exposed sensitive files
        """
        print_status("Checking for exposed sensitive files...")
        
        for path in self.SENSITIVE_FILES:
            try:
                response = self.http_request(
                    method="GET",
                    path=path,
                    allow_redirects=False
                )
                
                if response and response.status_code == 200:
                    content_length = len(response.content)
                    content_type = response.headers.get('Content-Type', 'unknown')
                    
                    is_sensitive = False
                    indicators = []
                    
                    if 'settings.php' in path:
                        is_sensitive = True
                        indicators.append('Drupal settings file')
                    
                    if 'password' in response.text.lower() or 'secret' in response.text.lower() or 'database' in response.text.lower():
                        is_sensitive = True
                        indicators.append('Contains sensitive configuration')
                    
                    if '.git' in path and ('ref:' in response.text or 'repositoryformatversion' in response.text.lower()):
                        is_sensitive = True
                        indicators.append('Git repository exposed')
                    
                    if is_sensitive or content_length > 0:
                        self.exposed_files.append({
                            'path': path,
                            'status_code': response.status_code,
                            'content_length': content_length,
                            'content_type': content_type,
                            'indicators': indicators,
                            'is_sensitive': is_sensitive
                        })
            except:
                pass

    def check_drupal_paths(self):
        """
        Check for Drupal-specific paths
        """
        print_status("Checking for Drupal-specific paths...")
        
        for path in self.DRUPAL_PATHS:
            try:
                response = self.http_request(
                    method="GET",
                    path=path,
                    allow_redirects=False
                )
                
                if response and response.status_code in [200, 301, 302, 403]:
                    # Check if it's actually a Drupal path
                    if 'drupal' in response.text.lower() or path in ['/user', '/admin', '/node']:
                        self.drupal_paths.append({
                            'path': path,
                            'status_code': response.status_code,
                            'accessible': True
                        })
            except:
                pass

    def check_misconfigurations(self):
        """
        Check for common Drupal misconfigurations
        """
        print_status("Checking for misconfigurations...")
        
        # Check if update.php is accessible
        try:
            response = self.http_request(method="GET", path="/update.php")
            if response and response.status_code == 200:
                self.misconfigurations.append({
                    'type': 'Information Disclosure',
                    'issue': 'update.php accessible',
                    'details': 'Update script is accessible without authentication',
                    'severity': 'Medium'
                })
        except:
            pass
        
        # Check if install.php is accessible
        try:
            response = self.http_request(method="GET", path="/install.php")
            if response and response.status_code == 200:
                self.misconfigurations.append({
                    'type': 'Information Disclosure',
                    'issue': 'install.php accessible',
                    'details': 'Install script is accessible',
                    'severity': 'Low'
                })
        except:
            pass
        
        # Check for exposed version information
        try:
            response = self.http_request(method="GET", path="/CHANGELOG.txt")
            if response and response.status_code == 200:
                self.misconfigurations.append({
                    'type': 'Information Disclosure',
                    'issue': 'CHANGELOG.txt exposed',
                    'details': 'Version information exposed',
                    'severity': 'Low'
                })
        except:
            pass

    def run(self):
        """
        Execute the Drupal vulnerability scan
        """
        self.drupal_version = None
        self.vulnerabilities = []
        self.misconfigurations = []
        self.exposed_files = []
        self.drupal_paths = []
        
        print_status("Starting Drupal vulnerability scan...")
        print_info(f"Target: {self.target}")
        print_info("")
        
        # Detect Drupal version
        print_status("Detecting Drupal version...")
        version = self.detect_drupal_version()
        self.drupal_version = version
        
        if version:
            print_success(f"Drupal version detected: {version}")
        else:
            print_warning("Could not detect Drupal version")
            print_info("Continuing with generic Drupal checks...")
        print_info("")
        
        # Check for CVEs
        if version:
            print_status("Checking for known CVEs...")
            self.check_cves()
            print_info("")
        
        # Check sensitive files
        self.check_sensitive_files()
        print_info("")
        
        # Check Drupal paths
        self.check_drupal_paths()
        print_info("")
        
        # Check misconfigurations
        self.check_misconfigurations()
        print_info("")
        
        # Summary
        print_status("=" * 60)
        print_status("Drupal Vulnerability Scan Summary")
        print_status("=" * 60)
        
        if version:
            print_info(f"Drupal Version: {version}")
        else:
            print_warning("Drupal Version: Not detected")
        
        print_info(f"CVEs Found: {len(self.vulnerabilities)}")
        print_info(f"Misconfigurations Found: {len(self.misconfigurations)}")
        print_info(f"Exposed Files Found: {len(self.exposed_files)}")
        print_info(f"Drupal Paths Found: {len(self.drupal_paths)}")
        print_status("=" * 60)
        print_info("")
        
        # Display CVEs
        if self.vulnerabilities:
            print_warning("Vulnerabilities (CVEs):")
            print_info("")
            table_data = []
            for vuln in self.vulnerabilities:
                table_data.append([
                    vuln['id'],
                    vuln['severity'],
                    vuln['name'],
                    vuln.get('version', 'N/A')
                ])
            print_table(['CVE ID', 'Severity', 'Name', 'Version'], table_data)
            print_info("")
        
        # Display misconfigurations
        if self.misconfigurations:
            print_status("Misconfigurations:")
            print_info("")
            for misconfig in self.misconfigurations:
                print_info(f" - [{misconfig['severity']}] {misconfig['type']}: {misconfig['issue']}")
                print_info(f"   - Details: {misconfig['details']}")
            print_info("")
        
        # Display exposed files
        if self.exposed_files:
            print_warning(f"Found {len(self.exposed_files)} exposed sensitive files")
            table_data = []
            for file_info in self.exposed_files:
                sensitivity = "SENSITIVE" if file_info['is_sensitive'] else "Exposed"
                table_data.append([
                    file_info['path'],
                    file_info['status_code'],
                    f"{file_info['content_length']} bytes",
                    sensitivity
                ])
            print_table(['Path', 'Status', 'Size', 'Type'], table_data)
            print_info("")
        
        # Display Drupal paths
        if self.drupal_paths:
            print_info(f"Found {len(self.drupal_paths)} accessible Drupal paths")
            for path_info in self.drupal_paths[:10]:  # Show first 10
                print_info(f"  - {path_info['path']} (Status: {path_info['status_code']})")
        
        return True
