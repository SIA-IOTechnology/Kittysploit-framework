#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
from lib.protocols.http.http_client import Http_client
import base64
import urllib.parse
import json
import re


class Module(Auxiliary, Http_client):

    __info__ = {
        'name': 'Java Deserialization Scanner',
        'description': 'Scans for Java deserialization vulnerabilities including unsafe deserialization in web applications, Java RMI, and JMX',
        'author': 'KittySploit Team',
        'tags': ['web', 'java', 'deserialization', 'scanner', 'security', 'rce'],
        'references': [
            'https://owasp.org/www-community/vulnerabilities/Deserialization_of_untrusted_data',
            'https://github.com/frohoff/ysoserial',
            'https://portswigger.net/web-security/deserialization',
        ]
    }

    # Java deserialization indicators
    JAVA_INDICATORS = [
        'java', 'jvm', 'jre', 'jdk',
        'apache', 'tomcat', 'jboss', 'weblogic', 'websphere',
        'spring', 'struts', 'hibernate',
        'serialization', 'deserialization',
        'objectinputstream', 'readobject',
    ]

    # Common endpoints that might deserialize data
    DESERIALIZATION_ENDPOINTS = [
        '/api',
        '/api/v1',
        '/rest',
        '/rest/api',
        '/rpc',
        '/rpc/execute',
        '/invoke',
        '/execute',
        '/serialize',
        '/deserialize',
        '/readObject',
        '/read',
        '/write',
        '/upload',
        '/file',
        '/data',
    ]

    # Java serialization magic bytes (AC ED 00 05)
    JAVA_SERIALIZATION_MAGIC = b'\xac\xed\x00\x05'

    def check(self):
        """
        Check if the target is accessible and might be using Java
        """
        try:
            response = self.http_request(method="GET", path="/")
            if response:
                # Check for Java indicators
                content = response.text.lower()
                headers = str(response.headers).lower()
                
                if any(indicator in content or indicator in headers for indicator in self.JAVA_INDICATORS):
                    return True
                
                # Check for Java application servers
                server_header = response.headers.get('Server', '').lower()
                java_servers = ['tomcat', 'jboss', 'weblogic', 'websphere', 'jetty', 'glassfish']
                if any(server in server_header for server in java_servers):
                    return True
                
                # Even if not detected, continue scanning
                return True
            return False
        except Exception as e:
            return False

    def detect_java_application(self):
        """
        Detect Java application server and framework
        """
        try:
            response = self.http_request(method="GET", path="/")
            if not response:
                return None
            
            server_header = response.headers.get('Server', '')
            content = response.text.lower()
            
            # Detect application server
            if 'tomcat' in server_header.lower():
                version_match = re.search(r'Apache[\/\s-]Tomcat[\/\s-]([\d\.]+)', server_header, re.IGNORECASE)
                if version_match:
                    return f"Apache Tomcat {version_match.group(1)}"
                return "Apache Tomcat"
            
            if 'jboss' in server_header.lower() or 'jboss' in content:
                return "JBoss"
            
            if 'weblogic' in server_header.lower() or 'weblogic' in content:
                return "WebLogic"
            
            if 'websphere' in server_header.lower() or 'websphere' in content:
                return "WebSphere"
            
            if 'jetty' in server_header.lower():
                return "Jetty"
            
            if 'glassfish' in server_header.lower():
                return "GlassFish"
            
            # Check for Spring
            if 'spring' in content or 'springframework' in content:
                return "Spring Framework"
            
            # Check for Struts
            if 'struts' in content:
                return "Apache Struts"
            
            return "Java Application (unknown server)"
        except Exception as e:
            print_debug(f"Error detecting Java application: {str(e)}")
            return None

    def create_java_serialized_object(self):
        """
        Create a simple Java serialized object for testing
        Note: This is a basic test payload, not a full exploit
        """
        # Java serialization header: AC ED 00 05 (magic bytes)
        # This is a minimal serialized object for detection
        magic_bytes = self.JAVA_SERIALIZATION_MAGIC
        
        # Basic serialized object structure (simplified)
        # In real scenarios, you would use ysoserial or similar tools
        payload = magic_bytes + b'\x73\x72'  # TC_OBJECT, TC_CLASSDESC
        
        return payload

    def test_deserialization_endpoint(self, endpoint, payload_data):
        """
        Test an endpoint for deserialization vulnerability
        
        Args:
            endpoint: The endpoint to test
            payload_data: Data to send (could be serialized object)
            
        Returns:
            dict: Test results
        """
        try:
            # Test with POST request containing serialized data
            headers = {
                'Content-Type': 'application/java-serialized-object',
                'Content-Type': 'application/x-java-serialized-object',
            }
            
            response = self.http_request(
                method="POST",
                path=endpoint,
                data=payload_data,
                headers=headers,
                allow_redirects=False
            )
            
            if not response:
                return {
                    'endpoint': endpoint,
                    'vulnerable': False,
                    'error': 'No response'
                }
            
            # Analyze response
            status_code = response.status_code
            content_length = len(response.content)
            
            # Check for deserialization error indicators
            is_vulnerable = False
            indicators = []
            
            error_indicators = [
                'java.io', 'readobject', 'objectinputstream',
                'classnotfoundexception', 'invalidclassexception',
                'serialization', 'deserialization',
                'exception', 'error', 'stack trace'
            ]
            
            response_lower = response.text.lower()
            for indicator in error_indicators:
                if indicator in response_lower:
                    is_vulnerable = True
                    indicators.append(f'Java error: {indicator}')
                    break
            
            # Check for unusual status codes
            if status_code in [500, 502, 503]:
                is_vulnerable = True
                indicators.append(f'Server error: {status_code}')
            
            return {
                'endpoint': endpoint,
                'vulnerable': is_vulnerable,
                'status_code': status_code,
                'content_length': content_length,
                'indicators': indicators,
                'response_preview': response.text[:200] if response.text else ''
            }
            
        except Exception as e:
            return {
                'endpoint': endpoint,
                'vulnerable': False,
                'error': str(e)
            }

    def test_json_deserialization(self, endpoint):
        """
        Test for JSON deserialization vulnerabilities (Jackson, Gson, etc.)
        
        Args:
            endpoint: The endpoint to test
            
        Returns:
            dict: Test results
        """
        try:
            # Test with malicious JSON payload
            malicious_json = {
                "@type": "java.lang.Runtime",
                "exec": "calc.exe"
            }
            
            headers = {
                'Content-Type': 'application/json'
            }
            
            response = self.http_request(
                method="POST",
                path=endpoint,
                json=malicious_json,
                headers=headers,
                allow_redirects=False
            )
            
            if not response:
                return {'endpoint': endpoint, 'vulnerable': False, 'error': 'No response'}
            
            # Check for indicators
            is_vulnerable = False
            indicators = []
            
            if response.status_code in [500, 502]:
                is_vulnerable = True
                indicators.append('Server error on JSON deserialization')
            
            if 'jackson' in response.text.lower() or 'gson' in response.text.lower():
                is_vulnerable = True
                indicators.append('JSON library detected')
            
            return {
                'endpoint': endpoint,
                'type': 'JSON deserialization',
                'vulnerable': is_vulnerable,
                'status_code': response.status_code,
                'indicators': indicators
            }
            
        except Exception as e:
            return {
                'endpoint': endpoint,
                'vulnerable': False,
                'error': str(e)
            }

    def run(self):
        """
        Execute the Java deserialization scan
        """
        self.vulnerabilities = []
        self.test_results = []
        
        print_status("Starting Java deserialization scan...")
        print_info(f"Target: {self.target}")
        print_info("")
        
        # Detect Java application
        print_status("Detecting Java application...")
        java_app = self.detect_java_application()
        if java_app:
            print_success(f"Java application detected: {java_app}")
        else:
            print_warning("Could not detect Java application")
            print_info("Continuing with generic deserialization tests...")
        print_info("")
        
        # Test deserialization endpoints
        print_status("Testing deserialization endpoints...")
        print_info("")
        
        # Create test payload
        test_payload = self.create_java_serialized_object()
        
        for endpoint in self.DESERIALIZATION_ENDPOINTS:
            print_info(f"Testing endpoint: {endpoint}")
            
            # Test Java serialization
            result = self.test_deserialization_endpoint(endpoint, test_payload)
            self.test_results.append(result)
            
            if result.get('vulnerable'):
                print_success(f"  [!] Potential deserialization vulnerability found!")
                print_info(f"      Endpoint: {endpoint}")
                print_info(f"      Indicators: {', '.join(result.get('indicators', []))}")
                print_info(f"      Status Code: {result.get('status_code')}")
                print_info("")
                self.vulnerabilities.append(result)
            
            # Test JSON deserialization
            json_result = self.test_json_deserialization(endpoint)
            self.test_results.append(json_result)
            
            if json_result.get('vulnerable'):
                print_success(f"  [!] Potential JSON deserialization vulnerability found!")
                print_info(f"      Endpoint: {endpoint}")
                print_info(f"      Indicators: {', '.join(json_result.get('indicators', []))}")
                print_info("")
                self.vulnerabilities.append(json_result)
        
        print_info("")
        
        # Summary
        print_status("=" * 60)
        print_status("Java Deserialization Scan Summary")
        print_status("=" * 60)
        
        if java_app:
            print_info(f"Java Application: {java_app}")
        else:
            print_warning("Java Application: Not detected")
        
        print_info(f"Total tests performed: {len(self.test_results)}")
        print_info(f"Potential vulnerabilities found: {len(self.vulnerabilities)}")
        print_status("=" * 60)
        print_info("")
        
        if self.vulnerabilities:
            print_warning("Potential deserialization vulnerabilities detected:")
            print_info("")
            
            table_data = []
            for vuln in self.vulnerabilities:
                vuln_type = vuln.get('type', 'Java deserialization')
                indicators = ', '.join(vuln.get('indicators', [])[:2])
                table_data.append([
                    vuln.get('endpoint', 'N/A'),
                    vuln_type,
                    vuln.get('status_code', 'N/A'),
                    indicators
                ])
            
            print_table(['Endpoint', 'Type', 'Status', 'Indicators'], table_data)
            print_info("")
            print_warning("IMPORTANT: These are potential vulnerabilities. Manual verification with tools like ysoserial is required.")
        else:
            print_info("No obvious deserialization vulnerabilities detected.")
            print_info("Note: This does not guarantee the application is secure. Manual testing with ysoserial is recommended.")
        
        return True
