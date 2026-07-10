from kittysploit import *
import json


class Module(BrowserAuxiliary):

	__info__ = {
		"name": "WebAuthn Probe",
		"description": "Detect WebAuthn / passkey support and platform authenticator availability",
		"author": "KittySploit Team",
		"browser": Browser.ALL,
		"platform": Platform.ALL,
		"session_type": SessionType.BROWSER,
	}

	def run(self):
		code_js = """
		(function() {
			const out = {
				supported: !!window.PublicKeyCredential,
				credentials_api: !!navigator.credentials,
				secure_context: window.isSecureContext === true,
				origin: window.location.origin,
				hints: []
			};

			if (!out.supported) {
				out.hints.push('PublicKeyCredential API is not exposed in this context');
				return JSON.stringify(out);
			}

			const tasks = [];

			if (typeof PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable === 'function') {
				tasks.push(
					PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable()
						.then(function(v) { out.platform_authenticator = !!v; })
						.catch(function(e) { out.platform_authenticator_error = e.message || String(e); })
				);
			}

			if (typeof PublicKeyCredential.isConditionalMediationAvailable === 'function') {
				tasks.push(
					PublicKeyCredential.isConditionalMediationAvailable()
						.then(function(v) { out.conditional_mediation = !!v; })
						.catch(function(e) { out.conditional_mediation_error = e.message || String(e); })
				);
			}

			if (typeof PublicKeyCredential.parseCreationOptionsFromJSON === 'function') {
				out.parse_creation_options_json = true;
			}
			if (typeof PublicKeyCredential.parseRequestOptionsFromJSON === 'function') {
				out.parse_request_options_json = true;
			}

			try {
				out.create_available = typeof navigator.credentials.create === 'function';
				out.get_available = typeof navigator.credentials.get === 'function';
			} catch (e) {
				out.credentials_error = e.message || String(e);
			}

			if (!out.secure_context) {
				out.hints.push('WebAuthn registration/assertion requires a secure context (HTTPS or localhost)');
			}
			if (out.platform_authenticator === true) {
				out.hints.push('Platform authenticator available (Windows Hello, Touch ID, etc.)');
			}
			if (out.conditional_mediation === true) {
				out.hints.push('Conditional UI / autofill passkeys may be available');
			}

			if (tasks.length === 0) {
				return JSON.stringify(out);
			}

			return Promise.all(tasks).then(function() {
				return JSON.stringify(out);
			});
		})();
		"""

		result = self.send_js_and_wait_for_response(code_js, timeout=10.0)
		if not result:
			print_error("Failed to probe WebAuthn support")
			return False

		if isinstance(result, str) and result.startswith("Error:"):
			print_error(result)
			return False

		try:
			data = json.loads(result)
		except json.JSONDecodeError as exc:
			print_error(f"Failed to parse WebAuthn probe response: {exc}")
			print_debug(f"Raw response: {result}")
			return False

		print_info("=" * 80)
		print_info("WebAuthn / Passkey probe")
		print_info("=" * 80)
		print_info(f"  Origin: {data.get('origin', 'unknown')}")
		print_info(f"  Secure context: {data.get('secure_context', False)}")
		print_info(f"  PublicKeyCredential: {data.get('supported', False)}")
		print_info(f"  navigator.credentials: {data.get('credentials_api', False)}")

		if data.get("supported"):
			if "platform_authenticator" in data:
				print_info(f"  Platform authenticator: {data.get('platform_authenticator')}")
			if "conditional_mediation" in data:
				print_info(f"  Conditional mediation: {data.get('conditional_mediation')}")
			print_info(f"  credentials.create(): {data.get('create_available', False)}")
			print_info(f"  credentials.get(): {data.get('get_available', False)}")
			if data.get("parse_creation_options_json"):
				print_info("  parseCreationOptionsFromJSON(): supported")
			if data.get("parse_request_options_json"):
				print_info("  parseRequestOptionsFromJSON(): supported")

		for key in ("platform_authenticator_error", "conditional_mediation_error", "credentials_error"):
			if data.get(key):
				print_warning(f"  {key}: {data[key]}")

		hints = data.get("hints") or []
		if hints:
			print_info("-" * 80)
			for hint in hints:
				print_info(f"  * {hint}")

		if not data.get("supported"):
			print_warning("WebAuthn is not available in this browser context")
		elif data.get("platform_authenticator"):
			print_success("Platform WebAuthn authenticator detected")
		else:
			print_success("WebAuthn API present (no platform authenticator reported)")

		print_info("=" * 80)
		print_status("Full probe result (JSON):")
		print_info(json.dumps(data, indent=2, ensure_ascii=False))
		return True
