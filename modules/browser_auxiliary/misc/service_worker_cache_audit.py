from kittysploit import *
import json


class Module(BrowserAuxiliary):

	__info__ = {
		"name": "Service Worker Cache Audit",
		"description": "List service workers, cache storage, and quota",
		"author": "KittySploit Team",
		"browser": Browser.ALL,
		"platform": Platform.ALL,
		"session_type": SessionType.BROWSER,
	}

	max_caches = OptInteger(10, "Max caches to inspect", False)
	max_entries = OptInteger(25, "Max URLs per cache", False)

	def run(self):
		max_caches_val = int(self.max_caches or 10)
		max_entries_val = int(self.max_entries or 25)

		code_js = f"""
		(function() {{
			const MAX_CACHES = {max_caches_val};
			const MAX_ENTRIES = {max_entries_val};

			function listCacheEntries(cacheName) {{
				return caches.open(cacheName).then(function(cache) {{
					return cache.keys().then(function(requests) {{
						const entries = requests.slice(0, MAX_ENTRIES).map(function(req) {{
							return {{
								url: req.url,
								method: req.method || 'GET'
							}};
						}});
						return {{
							name: cacheName,
							entry_count: requests.length,
							truncated: requests.length > MAX_ENTRIES,
							entries: entries
						}};
					}});
				}}).catch(function(err) {{
					return {{ name: cacheName, error: err.message || String(err) }};
				}});
			}}

			function auditCaches() {{
				if (!('caches' in window)) {{
					return Promise.resolve({{
						supported: false,
						error: 'Cache Storage API unavailable'
					}});
				}}
				return caches.keys().then(function(names) {{
					const selected = (names || []).slice(0, MAX_CACHES);
					return Promise.all(selected.map(listCacheEntries)).then(function(cacheData) {{
						return {{
							supported: true,
							cache_count: (names || []).length,
							caches_truncated: (names || []).length > MAX_CACHES,
							caches: cacheData
						}};
					}});
				}});
			}}

			function auditServiceWorkers() {{
				if (!('serviceWorker' in navigator)) {{
					return Promise.resolve({{
						supported: false,
						error: 'serviceWorker API unavailable'
					}});
				}}
				return navigator.serviceWorker.getRegistrations().then(function(regs) {{
					return {{
						supported: true,
						controller_active: !!navigator.serviceWorker.controller,
						controller_url: navigator.serviceWorker.controller
							? navigator.serviceWorker.controller.scriptURL
							: null,
						registration_count: regs.length,
						registrations: regs.map(function(reg) {{
							const worker = reg.active || reg.waiting || reg.installing;
							return {{
								scope: reg.scope,
								script_url: worker ? worker.scriptURL : null,
								state: worker ? worker.state : 'none',
								update_via_cache: reg.updateViaCache || 'imports'
							}};
						}})
					}};
				}});
			}}

			function auditStorageEstimate() {{
				if (!navigator.storage || typeof navigator.storage.estimate !== 'function') {{
					return Promise.resolve({{ supported: false }});
				}}
				return navigator.storage.estimate().then(function(est) {{
					return {{
						supported: true,
						quota: est.quota || 0,
						usage: est.usage || 0,
						usage_details: est.usageDetails || null
					}};
				}}).catch(function(err) {{
					return {{ supported: false, error: err.message || String(err) }};
				}});
			}}

			return Promise.all([
				auditServiceWorkers(),
				auditCaches(),
				auditStorageEstimate()
			]).then(function(results) {{
				return JSON.stringify({{
					origin: window.location.origin,
					url: window.location.href,
					secure_context: !!window.isSecureContext,
					service_workers: results[0],
					cache_storage: results[1],
					storage_estimate: results[2]
				}});
			}}).catch(function(err) {{
				return JSON.stringify({{ error: err.message || String(err) }});
			}});
		}})();
		"""

		result = self.send_js_and_wait_for_response(code_js, timeout=25.0)
		if not result:
			print_error("Failed to audit service worker / cache storage")
			return False

		if isinstance(result, str) and result.startswith("Error:"):
			print_error(result)
			return False

		try:
			data = json.loads(result)
		except json.JSONDecodeError as exc:
			print_error(f"Failed to parse cache audit response: {exc}")
			print_debug(f"Raw response: {result}")
			return False

		print_info("=" * 60)
		print_info("Service workers / cache")
		print_info(f"  Origin: {data.get('origin', '?')}")
		print_info(f"  Secure context: {data.get('secure_context', False)}")

		sw = data.get("service_workers", {})
		if not sw.get("supported", True):
			print_warning(f"Service workers: {sw.get('error', 'unavailable')}")
		else:
			print_info(f"  Service worker registrations: {sw.get('registration_count', 0)}")
			if sw.get("controller_active"):
				print_warning(f"  Active controller: {sw.get('controller_url', '')}")
			for reg in sw.get("registrations", []):
				print_info(f"    • scope={reg.get('scope', '?')} state={reg.get('state', '?')}")
				if reg.get("script_url"):
					print_info(f"      script: {reg['script_url']}")

		cache = data.get("cache_storage", {})
		if not cache.get("supported", True):
			print_warning(f"Cache Storage: {cache.get('error', 'unavailable')}")
		else:
			print_info(f"  Cache objects: {cache.get('cache_count', 0)}")
			for item in cache.get("caches", []):
				name = item.get("name", "?")
				if item.get("error"):
					print_warning(f"    Cache {name}: {item['error']}")
					continue
				truncated = " (truncated)" if item.get("truncated") else ""
				print_info(f"    Cache {name}: {item.get('entry_count', 0)} entr(y/ies){truncated}")
				for entry in item.get("entries", [])[:5]:
					print_info(f"      - {entry.get('method', 'GET')} {entry.get('url', '')}")
				remaining = item.get("entry_count", 0) - 5
				if remaining > 0:
					print_info(f"      ... {remaining} more URL(s)")

		storage = data.get("storage_estimate", {})
		if storage.get("supported"):
			quota = storage.get("quota", 0)
			usage = storage.get("usage", 0)
			print_info(f"  Storage quota: {usage} / {quota} bytes")
			if storage.get("usage_details"):
				print_info(f"  Usage details: {json.dumps(storage['usage_details'], ensure_ascii=False)}")

		if sw.get("registration_count", 0) > 0 or cache.get("cache_count", 0) > 0:
			print_warning("  SW or cache data present on this origin")
		else:
			print_status("No service worker registrations or cache objects found on this origin")

		return True
