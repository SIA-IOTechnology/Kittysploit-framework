from kittysploit import *
import json


class Module(BrowserAuxiliary):

	__info__ = {
		"name": "postMessage Attack Surface Map",
		"description": "Map postMessage usage, iframes, and optionally capture live message events",
		"author": "KittySploit Team",
		"browser": Browser.ALL,
		"platform": Platform.ALL,
		"session_type": SessionType.BROWSER,
	}

	listen_seconds = OptInteger(3, "Seconds to listen for live message events (0 = static only)", False)
	max_script_scan = OptInteger(50, "Max script elements to scan for postMessage patterns", False)

	def run(self):
		listen_s = max(0, int(self.listen_seconds or 3))
		max_scripts = max(5, int(self.max_script_scan or 50))
		listen_ms = listen_s * 1000

		code_js = f"""
		(function() {{
			const LISTEN_MS = {listen_ms};
			const MAX_SCRIPTS = {max_scripts};

			const out = {{
				ok: true,
				origin: window.location.origin,
				page_url: window.location.href,
				iframes: [],
				script_hits: [],
				handler_hints: [],
				live_messages: [],
				notes: []
			}};

			try {{
				document.querySelectorAll('iframe').forEach(function(frame, idx) {{
					let accessible = false;
					let frameOrigin = null;
					let frameHref = null;
					try {{
						const doc = frame.contentDocument || (frame.contentWindow && frame.contentWindow.document);
						if (doc) {{
							accessible = true;
							frameHref = frame.contentWindow.location.href;
							frameOrigin = frame.contentWindow.location.origin;
						}}
					}} catch (e) {{
						accessible = false;
					}}
					out.iframes.push({{
						index: idx,
						src: frame.getAttribute('src') || '',
						name: frame.getAttribute('name') || '',
						sandbox: frame.getAttribute('sandbox'),
						allow: frame.getAttribute('allow'),
						same_origin_accessible: accessible,
						frame_origin: frameOrigin,
						frame_href: frameHref
					}});
				}});
			}} catch (e) {{
				out.notes.push('iframe enum error: ' + (e.message || String(e)));
			}}

			const patterns = [
				{{ label: 'addEventListener_message', re: /addEventListener\\s*\\(\\s*['"]message['"]/i }},
				{{ label: 'onmessage_assignment', re: /\\.onmessage\\s*=/i }},
				{{ label: 'postMessage_call', re: /\\.postMessage\\s*\\(/i }},
				{{ label: 'origin_check_missing_hint', re: /addEventListener\\s*\\(\\s*['"]message['"][\\s\\S]{{0,200}}(?!origin)/i }},
				{{ label: 'event_data_sink', re: /event\\.data[\\s\\S]{{0,80}}(eval|innerHTML|document\\.write|Function\\()/i }}
			];

			try {{
				const scripts = Array.from(document.scripts || []).slice(0, MAX_SCRIPTS);
				scripts.forEach(function(script, idx) {{
					const src = script.src || null;
					const code = src ? '' : (script.textContent || '').slice(0, 120000);
					const blob = (src || '') + '\\n' + code;
					const matched = [];
					patterns.forEach(function(p) {{
						if (p.re.test(blob)) {{
							matched.push(p.label);
						}}
					}});
					if (matched.length) {{
						out.script_hits.push({{
							index: idx,
							src: src,
							inline: !src,
							matches: matched,
							snippet: src ? null : code.slice(0, 180).replace(/\\s+/g, ' ')
						}});
					}}
				}});
			}} catch (e) {{
				out.notes.push('script scan error: ' + (e.message || String(e)));
			}}

			if (typeof window.onmessage === 'function') {{
				out.handler_hints.push('window.onmessage is assigned');
			}}

			function listenLive() {{
				return new Promise(function(resolve) {{
					if (LISTEN_MS <= 0) {{
						resolve();
						return;
					}}
					function onMsg(ev) {{
						out.live_messages.push({{
							origin: ev.origin,
							data_preview: (function(d) {{
								try {{
									const s = typeof d === 'string' ? d : JSON.stringify(d);
									return s && s.length > 300 ? s.slice(0, 300) + '...' : s;
								}} catch (e) {{
									return String(d).slice(0, 300);
								}}
							}})(ev.data),
							source_same_window: ev.source === window,
							lastEventId: ev.lastEventId || null
						}});
					}}
					window.addEventListener('message', onMsg, true);
					setTimeout(function() {{
						window.removeEventListener('message', onMsg, true);
						resolve();
					}}, LISTEN_MS);
				}});
			}}

			return listenLive().then(function() {{
				if (out.script_hits.some(function(h) {{ return h.matches.indexOf('event_data_sink') !== -1; }})) {{
					out.notes.push('Potential unsafe sink near event.data — review script_hits');
				}}
				if (out.script_hits.some(function(h) {{ return h.matches.indexOf('addEventListener_message') !== -1; }})) {{
					out.notes.push('message listeners referenced in page scripts');
				}}
				return JSON.stringify(out);
			}});
		}})();
		"""

		wait = float(listen_s + 10)
		result = self.send_js_and_wait_for_response(code_js, timeout=wait)
		if not result:
			print_error("Failed to run postMessage map")
			return False
		if isinstance(result, str) and result.startswith("Error:"):
			print_error(result)
			return False

		try:
			data = json.loads(result)
		except json.JSONDecodeError as exc:
			print_error(f"Failed to parse postMessage map response: {exc}")
			print_debug(f"Raw response: {result}")
			return False

		print_info("=" * 60)
		print_info("postMessage Attack Surface")
		print_info(f"  Page: {data.get('page_url', '?')}")

		iframes = data.get("iframes") or []
		print_info(f"  Iframes: {len(iframes)}")
		for frame in iframes:
			access = "same-origin" if frame.get("same_origin_accessible") else "cross-origin/blocked"
			print_info(
				f"    [{frame.get('index')}] src={frame.get('src') or '(empty)'} ({access})"
			)
			if frame.get("sandbox") is not None:
				print_info(f"         sandbox={frame.get('sandbox')!r}")

		hits = data.get("script_hits") or []
		print_info("-" * 60)
		print_status(f"Script pattern hits: {len(hits)}")
		for hit in hits:
			where = hit.get("src") or f"inline[{hit.get('index')}]"
			print_warning(f"  {where}")
			print_info(f"    matches: {', '.join(hit.get('matches') or [])}")
			if hit.get("snippet"):
				print_info(f"    snippet: {hit['snippet']}")

		for hint in data.get("handler_hints") or []:
			print_warning(f"  Handler hint: {hint}")

		live = data.get("live_messages") or []
		print_info("-" * 60)
		print_status(f"Live messages captured ({listen_s}s): {len(live)}")
		for msg in live[:20]:
			print_info(f"  origin={msg.get('origin')} data={msg.get('data_preview')}")

		for note in data.get("notes") or []:
			print_info(f"  Note: {note}")

		return True
