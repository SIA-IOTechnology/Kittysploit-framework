from kittysploit import *
import json


class Module(BrowserAuxiliary):

	__info__ = {
		"name": "Browser Permissions Audit",
		"description": "Query sensitive browser permission states",
		"author": "KittySploit Team",
		"browser": Browser.ALL,
		"platform": Platform.ALL,
		"session_type": SessionType.BROWSER,
	}

	def run(self):
		code_js = """
		(function() {
			const permissionNames = [
				'geolocation',
				'notifications',
				'camera',
				'microphone',
				'clipboard-read',
				'clipboard-write',
				'persistent-storage',
				'background-sync',
				'accelerometer',
				'gyroscope',
				'magnetometer',
				'payment-handler'
			];

			const out = {
				origin: window.location.href,
				secure_context: !!window.isSecureContext,
				permissions_api: !!(navigator.permissions && navigator.permissions.query),
				results: [],
				features: {
					geolocation: !!navigator.geolocation,
					mediaDevices: !!(navigator.mediaDevices && navigator.mediaDevices.getUserMedia),
					clipboard: !!navigator.clipboard,
					serviceWorker: 'serviceWorker' in navigator,
					notifications: 'Notification' in window,
					notification_permission: (typeof Notification !== 'undefined') ? Notification.permission : 'unsupported'
				},
				errors: []
			};

			if (!out.permissions_api) {
				return Promise.resolve(JSON.stringify(out));
			}

			const tasks = permissionNames.map(function(name) {
				return navigator.permissions.query({ name: name })
					.then(function(status) {
						out.results.push({
							name: name,
							state: status.state,
							onchange_supported: typeof status.onchange === 'function'
						});
					})
					.catch(function(err) {
						out.errors.push({
							name: name,
							error: err.message || String(err)
						});
					});
			});

			return Promise.all(tasks).then(function() {
				return JSON.stringify(out);
			});
		})();
		"""

		result = self.send_js_and_wait_for_response(code_js, timeout=15.0)
		if not result:
			print_error("Failed to audit browser permissions")
			return False

		if isinstance(result, str) and result.startswith("Error:"):
			print_error(result)
			return False

		try:
			data = json.loads(result)
		except json.JSONDecodeError as exc:
			print_error(f"Failed to parse permissions audit response: {exc}")
			print_debug(f"Raw response: {result}")
			return False

		print_info("=" * 60)
		print_info("Permissions")
		print_info(f"  Origin: {data.get('origin', '?')}")
		print_info(f"  Secure context: {data.get('secure_context', False)}")

		if not data.get("permissions_api"):
			print_warning("Permissions API unavailable in this browser/context")
		else:
			granted = []
			denied = []
			prompt = []
			for item in data.get("results", []):
				state = (item.get("state") or "").lower()
				name = item.get("name", "?")
				if state == "granted":
					granted.append(name)
				elif state == "denied":
					denied.append(name)
				else:
					prompt.append(name)

			if granted:
				print_warning(f"  Granted: {', '.join(granted)}")
			if denied:
				print_info(f"  Denied: {', '.join(denied)}")
			if prompt:
				print_status(f"  Prompt/default: {', '.join(prompt)}")

		features = data.get("features", {})
		notif = features.get("notification_permission")
		if notif and notif != "unsupported":
			print_info(f"  Notification.permission: {notif}")

		errors = data.get("errors", [])
		if errors:
			print_info("-" * 60)
			print_status("Unsupported or blocked permission queries:")
			for err in errors[:10]:
				print_info(f"  {err.get('name', '?')}: {err.get('error', '')}")

		sensitive_granted = [
			r.get("name") for r in data.get("results", [])
			if (r.get("state") or "").lower() == "granted"
			and r.get("name") in ("camera", "microphone", "geolocation", "clipboard-read", "notifications")
		]
		if sensitive_granted:
			print_warning("  Sensitive permissions already granted")

		return True
