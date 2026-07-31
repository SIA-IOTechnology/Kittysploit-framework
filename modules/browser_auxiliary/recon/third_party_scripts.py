from kittysploit import *
import json


class Module(BrowserAuxiliary):

	__info__ = {
		"name": "Third-Party Script Inventory",
		"description": "Inventory script tags, classify first vs third-party, and flag known CDN / tracker hosts",
		"author": "KittySploit Team",
		"browser": Browser.ALL,
		"platform": Platform.ALL,
		"session_type": SessionType.BROWSER,
	}

	include_inline = OptBool(True, "Include inline scripts (size + hash preview)", False)
	include_modules = OptBool(True, "Include modulepreload / importmap hints", False)

	def run(self):
		include_inline = self._to_bool(self.include_inline)
		include_modules = self._to_bool(self.include_modules)

		code_js = f"""
		(function() {{
			const INCLUDE_INLINE = {str(include_inline).lower()};
			const INCLUDE_MODULES = {str(include_modules).lower()};
			const pageOrigin = location.origin;
			const scripts = [];
			const links = [];

			function hostOf(url) {{
				try {{ return new URL(url, location.href).host; }} catch (e) {{ return null; }}
			}}
			function isThird(url) {{
				try {{
					const u = new URL(url, location.href);
					return u.origin !== pageOrigin;
				}} catch (e) {{
					return false;
				}}
			}}

			Array.from(document.scripts || []).forEach(function(s, idx) {{
				const src = s.src || null;
				const item = {{
					index: idx,
					src: src,
					host: src ? hostOf(src) : null,
					third_party: src ? isThird(src) : false,
					async: !!s.async,
					defer: !!s.defer,
					type: s.type || 'text/javascript',
					crossorigin: s.crossOrigin || null,
					integrity: s.integrity || null,
					nonce: s.nonce || null,
					inline: !src
				}};
				if (!src && INCLUDE_INLINE) {{
					const text = s.textContent || '';
					item.inline_length = text.length;
					item.inline_preview = text.slice(0, 120).replace(/\\s+/g, ' ');
				}}
				if (src || INCLUDE_INLINE) {{
					scripts.push(item);
				}}
			}});

			if (INCLUDE_MODULES) {{
				document.querySelectorAll('link[rel=\"modulepreload\"], link[rel=\"preload\"][as=\"script\"], link[rel=\"preconnect\"], link[rel=\"dns-prefetch\"]').forEach(function(l, idx) {{
					const href = l.href || l.getAttribute('href');
					links.push({{
						index: idx,
						rel: l.rel,
						as: l.getAttribute('as'),
						href: href,
						host: href ? hostOf(href) : null,
						third_party: href ? isThird(href) : false
					}});
				}});
				const importMap = document.querySelector('script[type=\"importmap\"]');
				if (importMap) {{
					links.push({{
						index: -1,
						rel: 'importmap',
						href: null,
						inline_length: (importMap.textContent || '').length,
						preview: (importMap.textContent || '').slice(0, 200)
					}});
				}}
			}}

			return JSON.stringify({{
				ok: true,
				origin: pageOrigin,
				page_url: location.href,
				script_count: scripts.length,
				external_count: scripts.filter(function(s) {{ return !!s.src; }}).length,
				third_party_count: scripts.filter(function(s) {{ return s.third_party; }}).length,
				inline_count: scripts.filter(function(s) {{ return s.inline; }}).length,
				scripts: scripts,
				resource_hints: links
			}});
		}})();
		"""

		result = self.send_js_and_wait_for_response(code_js, timeout=15.0)
		if not result:
			print_error("Failed to inventory scripts")
			return False
		if isinstance(result, str) and result.startswith("Error:"):
			print_error(result)
			return False

		try:
			data = json.loads(result)
		except json.JSONDecodeError as exc:
			print_error(f"Failed to parse response: {exc}")
			return False

		known = {
			"googletagmanager.com": "Google Tag Manager",
			"google-analytics.com": "Google Analytics",
			"googleapis.com": "Google APIs / CDN",
			"gstatic.com": "Google static",
			"facebook.net": "Meta / Facebook",
			"connect.facebook.net": "Meta / Facebook",
			"doubleclick.net": "Google Ads",
			"cdn.jsdelivr.net": "jsDelivr",
			"cdnjs.cloudflare.com": "cdnjs",
			"unpkg.com": "unpkg",
			"ajax.cloudflare.com": "Cloudflare",
			"cloudflareinsights.com": "Cloudflare Insights",
			"hotjar.com": "Hotjar",
			"segment.com": "Segment",
			"segment.io": "Segment",
			"sentry.io": "Sentry",
			"newrelic.com": "New Relic",
			"clarity.ms": "Microsoft Clarity",
			"linkedin.com": "LinkedIn",
			"twitter.com": "X / Twitter",
			"x.com": "X / Twitter",
			"shopify.com": "Shopify",
			"stripe.com": "Stripe",
			"paypal.com": "PayPal",
			"intercom.io": "Intercom",
			"crisp.chat": "Crisp",
		}

		def classify_host(host: str):
			if not host:
				return None
			h = host.lower()
			for needle, label in known.items():
				if h == needle or h.endswith("." + needle):
					return label
			return None

		print_info("=" * 60)
		print_info("Third-Party Script Inventory")
		print_info(f"  Page: {data.get('page_url')}")
		print_info(
			f"  Scripts: {data.get('script_count')} "
			f"(external={data.get('external_count')}, "
			f"third-party={data.get('third_party_count')}, "
			f"inline={data.get('inline_count')})"
		)

		third = [s for s in (data.get("scripts") or []) if s.get("third_party")]
		first = [s for s in (data.get("scripts") or []) if s.get("src") and not s.get("third_party")]

		if third:
			print_info("-" * 60)
			print_warning(f"Third-party scripts ({len(third)}):")
			for s in third:
				label = classify_host(s.get("host") or "")
				tag = f" [{label}]" if label else ""
				attrs = []
				if s.get("async"):
					attrs.append("async")
				if s.get("defer"):
					attrs.append("defer")
				if s.get("integrity"):
					attrs.append("sri")
				attr_s = f" ({', '.join(attrs)})" if attrs else ""
				print_info(f"  {s.get('host')}{tag}{attr_s}")
				print_info(f"    {s.get('src')}")

		if first:
			print_info("-" * 60)
			print_status(f"First-party external scripts ({len(first)}):")
			for s in first[:20]:
				print_info(f"  {s.get('src')}")

		hints = data.get("resource_hints") or []
		if hints:
			print_info("-" * 60)
			print_status(f"Resource hints / importmap ({len(hints)}):")
			for h in hints[:20]:
				print_info(f"  [{h.get('rel')}] {h.get('href') or h.get('preview') or ''}")

		# Supply-chain risk hints
		risks = []
		for s in third:
			if not s.get("integrity"):
				host = s.get("host") or ""
				label = classify_host(host)
				if label and any(x in (label or "").lower() for x in ("cdn", "jsdelivr", "unpkg", "cdnjs")):
					risks.append(f"{host} loaded without SRI")
		if risks:
			print_warning("Supply-chain notes:")
			for r in risks[:10]:
				print_info(f"  {r}")

		return True
