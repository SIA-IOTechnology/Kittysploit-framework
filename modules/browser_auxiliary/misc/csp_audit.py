from kittysploit import *
import json


class Module(BrowserAuxiliary):

	__info__ = {
		"name": "CSP Audit",
		"description": "Probe CSP meta tags and inline/eval restrictions",
		"author": "KittySploit Team",
		"browser": Browser.ALL,
		"platform": Platform.ALL,
		"session_type": SessionType.BROWSER,
	}

	def run(self):
		code_js = """
		(function() {
			const out = {
				origin: window.location.origin,
				url: window.location.href,
				secure_context: !!window.isSecureContext,
				meta_csp: [],
				meta_csp_report_only: [],
				trusted_types_required: false,
				trusted_types_policy_count: 0,
				probes: {
					inline_script_blocked: false,
					eval_blocked: false,
					function_constructor_blocked: false,
					blob_worker_blocked: false
				},
				notes: []
			};

			document.querySelectorAll('meta[http-equiv]').forEach(function(meta) {
				const equiv = (meta.getAttribute('http-equiv') || '').toLowerCase();
				const content = meta.getAttribute('content') || '';
				if (equiv === 'content-security-policy') {
					out.meta_csp.push(content);
				}
				if (equiv === 'content-security-policy-report-only') {
					out.meta_csp_report_only.push(content);
				}
			});

			if (window.trustedTypes && trustedTypes.createPolicy) {
				try {
					trustedTypes.createPolicy('kittysploit-audit', {
						createHTML: function(s) { return s; },
						createScript: function(s) { return s; },
						createScriptURL: function(s) { return s; }
					});
					out.trusted_types_policy_count = (trustedTypes.getPolicyNames
						? trustedTypes.getPolicyNames().length
						: 1);
				} catch (e) {
					out.trusted_types_required = true;
					out.notes.push('Trusted Types policy creation blocked: ' + (e.message || String(e)));
				}
			}

			try {
				const s = document.createElement('script');
				s.textContent = 'window.__ks_csp_inline_probe = 1;';
				document.head.appendChild(s);
				document.head.removeChild(s);
				out.probes.inline_script_blocked = (window.__ks_csp_inline_probe !== 1);
				try { delete window.__ks_csp_inline_probe; } catch (e) {}
			} catch (e) {
				out.probes.inline_script_blocked = true;
				out.notes.push('Inline script probe error: ' + (e.message || String(e)));
			}

			try {
				eval('window.__ks_csp_eval_probe = 1');
				out.probes.eval_blocked = (window.__ks_csp_eval_probe !== 1);
				try { delete window.__ks_csp_eval_probe; } catch (e) {}
			} catch (e) {
				out.probes.eval_blocked = true;
			}

			try {
				const Fn = Function('window.__ks_csp_fn_probe = 1');
				Fn();
				out.probes.function_constructor_blocked = (window.__ks_csp_fn_probe !== 1);
				try { delete window.__ks_csp_fn_probe; } catch (e) {}
			} catch (e) {
				out.probes.function_constructor_blocked = true;
			}

			try {
				const blob = new Blob(['postMessage("ok")'], { type: 'application/javascript' });
				const url = URL.createObjectURL(blob);
				const worker = new Worker(url);
				worker.terminate();
				URL.revokeObjectURL(url);
				out.probes.blob_worker_blocked = false;
			} catch (e) {
				out.probes.blob_worker_blocked = true;
			}

			if (!out.meta_csp.length && !out.meta_csp_report_only.length) {
				out.notes.push('No CSP meta tags found — response headers may still enforce CSP (not visible to page JS).');
			}

			return JSON.stringify(out);
		})();
		"""

		result = self.send_js_and_wait_for_response(code_js, timeout=12.0)
		if not result:
			print_error("Failed to audit CSP posture")
			return False

		if isinstance(result, str) and result.startswith("Error:"):
			print_error(result)
			return False

		try:
			data = json.loads(result)
		except json.JSONDecodeError as exc:
			print_error(f"Failed to parse CSP audit response: {exc}")
			print_debug(f"Raw response: {result}")
			return False

		print_info("=" * 60)
		print_info("CSP")
		print_info(f"  Origin: {data.get('origin', '?')}")

		meta_csp = data.get("meta_csp", [])
		meta_ro = data.get("meta_csp_report_only", [])
		if meta_csp:
			for idx, policy in enumerate(meta_csp):
				print_info(f"  CSP meta[{idx}]: {policy[:200]}{'...' if len(policy) > 200 else ''}")
		else:
			print_status("  No enforcing CSP meta tag detected")

		if meta_ro:
			for idx, policy in enumerate(meta_ro):
				print_info(f"  CSP-Report-Only meta[{idx}]: {policy[:200]}")

		probes = data.get("probes", {})
		blockers = []
		if probes.get("inline_script_blocked"):
			blockers.append("inline scripts")
		if probes.get("eval_blocked"):
			blockers.append("eval")
		if probes.get("function_constructor_blocked"):
			blockers.append("Function constructor")
		if probes.get("blob_worker_blocked"):
			blockers.append("blob workers")
		if data.get("trusted_types_required"):
			blockers.append("Trusted Types")

		print_info("-" * 60)
		if blockers:
			print_warning(f"  Execution restrictions detected: {', '.join(blockers)}")
			print_warning("  Dynamic JS may be blocked")
		else:
			print_status("  Probes did not hit CSP blocks")

		for note in data.get("notes", []):
			print_info(f"  Note: {note}")

		return True
