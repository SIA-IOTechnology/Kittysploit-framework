from kittysploit import *

class Module(BrowserAuxiliary):

	__info__ = {
		"name": "XSS DOM Scanner",
		"description": "Advanced XSS vulnerability scanner that analyzes the DOM for potential XSS vulnerabilities (DOM-based, reflected, stored)",
		"author": "KittySploit Team",
		"browser": Browser.ALL,
		"platform": Platform.ALL,
		"session_type": SessionType.BROWSER,
	}	
	
	scan_depth = OptInteger(3, "Scan depth for recursive DOM analysis (1-5, higher = more thorough but slower)", False)
	check_sources = OptBool(True, "Check for dangerous data sources (URL params, cookies, localStorage, etc.)", False)
	check_sinks = OptBool(True, "Check for dangerous sinks (innerHTML, eval, document.write, etc.)", False)
	check_events = OptBool(True, "Check for event handlers (onclick, onerror, etc.)", False)
	check_forms = OptBool(True, "Check form inputs and handlers", False)
	check_csp = OptBool(True, "Check Content Security Policy", False)
	check_dom_clobbering = OptBool(True, "Detect DOM Clobbering patterns (duplicate ids, reserved names)", False)
	test_payloads = OptBool(True, "Test with XSS payloads to verify vulnerabilities", False)
	detailed_report = OptBool(True, "Generate detailed vulnerability report", False)

	def run(self):
		"""Scan DOM for XSS vulnerabilities"""
		
		js_code = rf"""
		(function() {{
			const config = {{
				scanDepth: Math.max(1, Math.min(5, {self.scan_depth})),
				checkSources: {str(self.check_sources).lower()},
				checkSinks: {str(self.check_sinks).lower()},
				checkEvents: {str(self.check_events).lower()},
				checkForms: {str(self.check_forms).lower()},
				checkCSP: {str(self.check_csp).lower()},
				checkDomClobbering: {str(self.check_dom_clobbering).lower()},
				testPayloads: {str(self.test_payloads).lower()},
				detailedReport: {str(self.detailed_report).lower()}
			}};
			
			const scanner = {{
				config,
				vulnerabilities: [],
				visitedNodes: new WeakSet(),
				domSnapshot: null,
				userControlledTokens: [],
				domIdMap: new Map(),
				domNameMap: new Map(),
				reservedHits: [],
				stats: {{
					nodesVisited: 0,
					attributesChecked: 0,
					scriptsInspected: 0,
					startTime: performance.now()
				}},
				payloads: [
					'<img src=x onerror=alert(1)>',
					'\"><svg/onload=alert(1)>',
					'<svg onload=confirm(1)>',
					'<script>alert(1)</script>',
					'javascript:alert(1)',
					'data:text/html,<svg onload=alert(1)>',
					'\"><img src=x onerror=alert(document.domain)>',
					'<iframe srcdoc="<script>alert(1)</script>"></iframe>',
					'<body onload=alert(1)>',
					'<math href="javascript:alert(1)">'
				],
				secondaryPayloads: [
					'\"><script>alert(String.fromCharCode(88,83,83))</script>',
					'<svg><script>//<svg onload=alert(1)></script>',
					'\"><iframe src=javascript:alert(1)>',
					'\"><img/src/onerror=alert(1)>',
					'<a href=javascript:alert(1)>click</a>',
					'\"><math href=xlink:href=javascript:alert(1)>',
					'\"><form action=javascript:alert(1)><input type=submit>'
				],
				dangerousAttributeSet: new Set([
					'src','srcdoc','href','xlink:href','data','action','formaction','poster','code','value','style','background','lowsrc','srcset','cite','codebase','dynsrc','hrefset','target'
				]),
				dangerousSchemes: ['javascript:', 'data:text/html', 'data:text/xml', 'vbscript:', 'file:', 'filesystem:'],
				interestingTags: new Set(['SCRIPT','IFRAME','IMG','SVG','MATH','OBJECT','EMBED','VIDEO','AUDIO','LINK','A','FORM','INPUT','TEXTAREA','SELECT','TEMPLATE','BODY','DIV','SPAN','DETAILS']),
				domClobberReserved: new Set(['constructor','__proto__','prototype','contentwindow','contentdocument','location','onload','onerror','document','write','cookie','body','forms','parent','self','top','history','name']),
				formReservedNames: new Set(['action','method','submit','length','target','attributes']),
				
				addVuln: function(type, severity, location, description, code, element) {{
					this.vulnerabilities.push({{
						type: type,
						severity: severity,
						location: location,
						description: description,
						code: code || '',
						element: element ? {{
							tagName: element.tagName,
							id: element.id || '',
							className: element.className || '',
							outerHTML: element.outerHTML ? element.outerHTML.substring(0, 200) : ''
						}} : null,
						timestamp: new Date().toISOString()
					}});
				}},
				
				init: function() {{
					this.userControlledTokens = this.collectUserControlledTokens();
				}},
				
				collectUserControlledTokens: function() {{
					const tokens = new Set();
					const addToken = value => {{
						if (!value || typeof value !== 'string') return;
						const trimmed = value.trim();
						if (!trimmed || trimmed.length > 1000) return;
						tokens.add(trimmed.toLowerCase());
					}};
					const params = new URLSearchParams(window.location.search);
					params.forEach((value, key) => {{
						addToken(value);
						addToken(key);
					}});
					if (window.location.hash) {{
						addToken(window.location.hash.substring(1));
					}}
					if (window.name) {{
						addToken(window.name);
					}}
					if (document.referrer) {{
						addToken(document.referrer);
					}}
					try {{
						if (document.cookie) {{
							document.cookie.split(';').forEach(cookie => {{
								const parts = cookie.split('=');
								if (parts.length) {{
									addToken(parts[0]);
									addToken(parts.slice(1).join('='));
								}}
							}});
						}}
					}} catch (e) {{}}
					try {{
						for (let i = 0; i < localStorage.length; i++) {{
							const key = localStorage.key(i);
							addToken(key);
							addToken(localStorage.getItem(key));
						}}
					}} catch (e) {{}}
					try {{
						for (let i = 0; i < sessionStorage.length; i++) {{
							const key = sessionStorage.key(i);
							addToken(key);
							addToken(sessionStorage.getItem(key));
						}}
					}} catch (e) {{}}
					return Array.from(tokens);
				}},
				
				isUserControlled: function(str) {{
					if (!str || typeof str !== 'string') return false;
					const lower = str.toLowerCase();
					return this.userControlledTokens.some(token => token && lower.includes(token));
				}},
				
				containsXSSPatterns: function(str) {{
					if (!str || typeof str !== 'string') return false;
					const patterns = [
						/<\s*script/i,
						/<\s*svg/i,
						/on[a-z]+\s*=/i,
						/javascript:/i,
						/data:\s*text\//i,
						/vbscript:/i,
						/srcdoc/i,
						/eval\s*\(/i,
						/new\s+Function/i,
						/document\.write/i,
						/innerHTML/i,
						/outerHTML/i,
						/insertAdjacentHTML/i,
						/src\s*=\s*["']?javascript/i,
						/<iframe/i,
						/<math/i
					];
					return patterns.some(pattern => pattern.test(str));
				}},
				
				usesDangerousScheme: function(value) {{
					if (!value || typeof value !== 'string') return false;
					const lower = value.trim().toLowerCase();
					return this.dangerousSchemes.some(scheme => lower.startsWith(scheme));
				}},
				
				getDomSnapshot: function() {{
					if (this.domSnapshot) return this.domSnapshot;
					try {{
						this.domSnapshot = document.documentElement ? document.documentElement.outerHTML : '';
					}} catch (e) {{
						this.domSnapshot = '';
					}}
					return this.domSnapshot;
				}},
				
				analyzeAttribute: function(element, attrName) {{
					if (!element || !attrName) return;
					const value = element.getAttribute(attrName);
					if (value === null || value === undefined) return;
					this.stats.attributesChecked++;
					const lower = attrName.toLowerCase();
					if (lower === 'id' || lower === 'name') {{
						this.trackDomName(element, lower, value);
					}}
					if (lower.startsWith('on')) {{
						if (this.config.checkEvents) {{
							const severity = this.isUserControlled(value) ? 'High' : 'Medium';
							const description = this.isUserControlled(value)
								? `Event handler ${{attrName}} appears to use user-controlled data`
								: `Inline event handler ${{attrName}} detected`;
							this.addVuln(
								'Event Handler XSS',
								severity,
								attrName,
								description,
								`${{attrName}}="${{value.substring(0, 150)}}..."`,
								element
							);
						}}
						return;
					}}
					if (!this.config.checkSinks) return;
					if (this.dangerousAttributeSet.has(lower) || this.containsXSSPatterns(value) || this.usesDangerousScheme(value)) {{
						if (this.isUserControlled(value) || this.containsXSSPatterns(value) || this.usesDangerousScheme(value)) {{
							this.addVuln(
								'DOM-based XSS',
								this.isUserControlled(value) ? 'High' : 'Medium',
								attrName,
								`Attribute "${{attrName}}" contains potentially dangerous data`,
								`${{attrName}}="${{value.substring(0, 150)}}..."`,
								element
							);
						}}
					}}
					if (lower === 'style' && /expression|url\(\s*javascript:/i.test(value)) {{
						this.addVuln(
							'Style Injection',
							'Medium',
							'style',
							'Style attribute contains expression() or javascript: url',
							`${{attrName}}="${{value.substring(0, 150)}}..."`,
							element
						);
					}}
				}},
				
				trackDomName: function(element, attr, value) {{
					if (!this.config.checkDomClobbering) return;
					const normalized = (value || '').trim();
					if (!normalized) return;
					const map = attr === 'id' ? this.domIdMap : this.domNameMap;
					if (!map.has(normalized)) {{
						map.set(normalized, []);
					}}
					map.get(normalized).push(element);
					const lower = normalized.toLowerCase();
					if (this.domClobberReserved.has(lower)) {{
						this.reservedHits.push({{
							type: attr,
							name: normalized,
							element: element,
							reason: 'Reserved browser property name (DOM clobbering risk)'
						}});
					}}
					if (attr === 'name' && element.tagName === 'INPUT' && this.formReservedNames.has(lower)) {{
						this.reservedHits.push({{
							type: attr,
							name: normalized,
							element: element,
							reason: 'Input name can override parent form property'
						}});
					}}
				}},
				
				analyzeNode: function(element) {{
					if (!element || element.nodeType !== 1) return;
					this.stats.nodesVisited++;
					const attrNames = element.getAttributeNames
						? element.getAttributeNames()
						: Array.from(element.attributes || []).map(attr => attr.name);
					attrNames.forEach(attr => this.analyzeAttribute(element, attr));
					if (this.config.checkForms) {{
						if (element.tagName === 'FORM') {{
							this.analyzeFormElement(element);
						}} else if (['INPUT', 'TEXTAREA', 'SELECT', 'BUTTON'].includes(element.tagName)) {{
							this.analyzeFormElement(element);
						}}
					}}
					if (this.config.checkSinks) {{
						this.inspectElementContent(element);
					}}
				}},
				
				inspectElementContent: function(element) {{
					const tag = element.tagName || '';
					if ((this.interestingTags.has(tag) || element.childElementCount === 0) && element.innerHTML) {{
						const html = element.innerHTML;
						if (html && (this.containsXSSPatterns(html) || this.isUserControlled(html))) {{
							this.addVuln(
								'DOM-based XSS',
								this.isUserControlled(html) ? 'High' : 'Medium',
								`${{tag}}.innerHTML`,
								`${{tag}} innerHTML contains suspicious content`,
								html.substring(0, 180),
								element
							);
						}}
					}}
					if (tag === 'SCRIPT') {{
						const code = element.textContent || '';
						if (code && /location\.|document\.(URL|cookie|referrer)/i.test(code) && /(innerHTML|document\.write|eval|Function|setTimeout|setInterval)/i.test(code)) {{
							this.addVuln(
								'DOM XSS Gadget',
								'High',
								'script inline',
								'Inline script reads user input and writes to a dangerous sink',
								code.substring(0, 200),
								element
							);
						}}
					}}
				}},
				
				analyzeFormElement: function(element) {{
					if (element.tagName === 'FORM') {{
						if (element.action && (this.isUserControlled(element.action) || this.usesDangerousScheme(element.action))) {{
							this.addVuln(
								'Form Action Injection',
								'High',
								'form.action',
								'Form action appears user-controllable or uses dangerous scheme',
								element.action.substring(0, 180),
								element
							);
						}}
						return;
					}}
					if (element.tagName === 'INPUT' || element.tagName === 'TEXTAREA' || element.tagName === 'SELECT') {{
						const value = element.value || '';
						if (value && (this.containsXSSPatterns(value) || this.isUserControlled(value))) {{
							this.addVuln(
								'Reflected XSS',
								'Medium',
								'input.value',
								'Input value contains suspicious payload',
								value.substring(0, 150),
								element
							);
						}}
					}}
				}},
				
				scanDomTree: function() {{
					const root = document.documentElement;
					if (!root) return;
					const queue = [{{ node: root, depth: 0 }}];
					while (queue.length) {{
						const current = queue.shift();
						const node = current.node;
						const depth = current.depth;
						if (!node || node.nodeType !== 1) continue;
						if (this.visitedNodes.has(node)) continue;
						this.visitedNodes.add(node);
						this.analyzeNode(node);
						if (depth >= this.config.scanDepth) continue;
						for (let i = 0; i < node.children.length; i++) {{
							queue.push({{ node: node.children[i], depth: depth + 1 }});
						}}
					}}
				}},
				
				checkDomClobberingFindings: function() {{
					if (!this.config.checkDomClobbering) return;
					const reportDuplicates = (map, attrName) => {{
						map.forEach((elements, value) => {{
							if (elements.length > 1) {{
								this.addVuln(
									'DOM Clobbering',
									'Medium',
									attrName,
									`Multiple elements share ${attrName} "${value}"`,
									`${attrName}="${value}" occurs ${elements.length} times`,
									elements[0]
								);
							}}
						}});
					}};
					reportDuplicates(this.domIdMap, 'id');
					reportDuplicates(this.domNameMap, 'name');
					this.reservedHits.forEach(hit => {{
						this.addVuln(
							'DOM Clobbering',
							'High',
							`${{hit.type}}="${{hit.name}}"`,
							hit.reason,
							`${{hit.type}}="${{hit.name}}"`,
							hit.element
						);
					}});
				}},
				
				checkSourceReflection: function() {{
					if (!this.config.checkSources) return;
					const snapshot = this.getDomSnapshot();
					if (!snapshot) return;
					const params = new URLSearchParams(window.location.search);
					params.forEach((value, key) => {{
						if (!value || value.length > 500) return;
						const decoded = decodeURIComponent(value);
						if (decoded && snapshot.includes(decoded)) {{
							this.addVuln(
								'Reflected XSS',
								'High',
								`URL parameter "${{key}}"`,
								`Parameter "${{key}}" is reflected into the DOM`,
								decoded.substring(0, 150),
								null
							);
						}}
					}});
					if (window.location.hash) {{
						const hashValue = window.location.hash.substring(1);
						if (hashValue && hashValue.length <= 500 && snapshot.includes(hashValue)) {{
							this.addVuln(
								'Reflected XSS',
								'High',
								'URL hash',
								'URL hash value is reflected into DOM',
								hashValue.substring(0, 150),
								null
							);
						}}
					}}
				}},
				
				checkRawSources: function() {{
					if (!this.config.checkSources) return;
					const maybeReport = (value, label, severity = 'Medium') => {{
						if (!value || typeof value !== 'string') return;
						if (this.containsXSSPatterns(value) || this.usesDangerousScheme(value)) {{
							this.addVuln(
								'Potential XSS Source',
								severity,
								label,
								`${{label}} contains XSS-like payload`,
								value.substring(0, 150),
								null
							);
						}}
					}};
					const params = new URLSearchParams(window.location.search);
					params.forEach((value, key) => {{
						maybeReport(value, `URL parameter "${{key}}"`, 'High');
					}});
					if (window.location.hash) {{
						maybeReport(window.location.hash.substring(1), 'URL hash', 'High');
					}}
					if (document.cookie) {{
						document.cookie.split(';').forEach(cookie => {{
							const [name, ...rest] = cookie.split('=');
							const val = rest.join('=');
							maybeReport(val, `Cookie "${{(name || '').trim()}}"`);
						}});
					}}
					try {{
						for (let i = 0; i < localStorage.length; i++) {{
							const key = localStorage.key(i);
							maybeReport(localStorage.getItem(key), `localStorage["${{key}}"]`);
						}}
					}} catch (e) {{}}
					try {{
						for (let i = 0; i < sessionStorage.length; i++) {{
							const key = sessionStorage.key(i);
							maybeReport(sessionStorage.getItem(key), `sessionStorage["${{key}}"]`);
						}}
					}} catch (e) {{}}
					if (window.name) {{
						maybeReport(window.name, 'window.name');
					}}
				}},
				
				testPayloadReflections: function() {{
					if (!this.config.testPayloads) return;
					const snapshot = this.getDomSnapshot();
					if (!snapshot) return;
					const payloadsToCheck = this.payloads.concat(this.secondaryPayloads);
					payloadsToCheck.forEach(payload => {{
						if (snapshot.includes(payload)) {{
							this.addVuln(
								'Stored XSS',
								'High',
								'DOM snapshot',
								`Known payload pattern detected: ${{payload.substring(0, 120)}}`,
								payload.substring(0, 150),
								null
							);
						}}
					}});
				}},
				
				analyzeScripts: function() {{
					if (!this.config.checkSinks) return;
					const scripts = document.querySelectorAll('script');
					scripts.forEach(script => {{
						this.stats.scriptsInspected++;
						const code = script.textContent || '';
						if (!code) return;
						if (/document\.write\s*\(/i.test(code) && /location|hash|search|cookie|localStorage/i.test(code)) {{
							this.addVuln(
								'DOM XSS Gadget',
								'High',
								'script',
								'Script writes user-controlled data using document.write',
								code.substring(0, 200),
								script
							);
						}}
						if (/(innerHTML|outerHTML|insertAdjacentHTML)/i.test(code) && /location|hash|search|cookie|localStorage|sessionStorage/i.test(code)) {{
							this.addVuln(
								'DOM XSS Gadget',
								'Medium',
								'script',
								'Script mixes DOM sinks with user input sources',
								code.substring(0, 200),
								script
							);
						}}
					}});
				}},
				
				checkCSP: function() {{
					if (!this.config.checkCSP) return;
					const metaTags = document.querySelectorAll('meta[http-equiv="Content-Security-Policy"]');
					if (!metaTags.length) {{
						this.addVuln(
							'Missing CSP',
							'Medium',
							'Content-Security-Policy',
							'No Content-Security-Policy meta tag detected',
							'CSP missing in DOM',
							null
						);
						return;
					}}
					metaTags.forEach(meta => {{
						const csp = meta.content || '';
						if (!csp) return;
						if (/unsafe-inline|unsafe-eval|data:/i.test(csp)) {{
							this.addVuln(
								'Weak CSP',
								'Medium',
								'Content-Security-Policy',
								'CSP allows unsafe-inline/unsafe-eval or data: sources',
								csp.substring(0, 200),
								meta
							);
						}}
					}});
				}},
				
				checkForms: function() {{
					if (!this.config.checkForms) return;
					const forms = document.querySelectorAll('form');
					forms.forEach(form => {{
						if (form.action && this.isUserControlled(form.action)) {{
							this.addVuln(
								'Form Action XSS',
								'High',
								'form.action',
								'Form action contains potentially user-controlled data',
								`form.action = "${{form.action}}"`,
								form
							);
						}}
						const inputs = form.querySelectorAll('input, textarea, select');
						inputs.forEach(input => {{
							if (input.value) {{
								const value = input.value;
								if (this.containsXSSPatterns(value)) {{
									this.addVuln(
										'Reflected XSS',
										'Medium',
										'input.value',
										'Input value contains XSS-like patterns',
										`input.value = "${{value.substring(0, 100)}}..."`,
										input
									);
								}}
							}}
						}});
					}});
				}},
				
				checkSources: function() {{
					// Deprecated placeholder to keep backward compatibility
					this.checkRawSources();
				}},
				
				run: function() {{
					this.init();
					this.checkRawSources();
					this.checkCSP();
					this.checkForms();
					this.scanDomTree();
					this.analyzeScripts();
					this.checkSourceReflection();
					this.testPayloadReflections();
					this.checkDomClobberingFindings();
					const duration = Math.round(performance.now() - this.stats.startTime);
					this.stats.durationMs = duration;
					return this.vulnerabilities;
				}}
			}};
			
			const results = scanner.run();
			return JSON.stringify({{
				url: window.location.href,
				timestamp: new Date().toISOString(),
				totalVulnerabilities: results.length,
				vulnerabilities: results,
				summary: {{
					high: results.filter(v => v.severity === 'High').length,
					medium: results.filter(v => v.severity === 'Medium').length,
					low: results.filter(v => v.severity === 'Low').length
				}},
				stats: scanner.stats
			}}, null, 2);
		}})();
		"""
		
		result = self.send_js_and_wait_for_response(js_code, timeout=30.0)
		
		if result:
			try:
				import json
				scan_results = json.loads(result)
				
				print_success("XSS DOM scan completed!")
				print_info(f"URL: {scan_results.get('url', 'unknown')}")
				print_info(f"Total vulnerabilities found: {scan_results.get('totalVulnerabilities', 0)}")
				
				summary = scan_results.get('summary', {})
				print_info(f"  - High severity: {summary.get('high', 0)}")
				print_info(f"  - Medium severity: {summary.get('medium', 0)}")
				print_info(f"  - Low severity: {summary.get('low', 0)}")
				
				stats = scan_results.get('stats', {})
				if stats:
					print_info(
						"Scan stats - Nodes: {nodes}, Attrs: {attrs}, Scripts: {scripts}, Duration: {duration} ms".format(
							nodes=stats.get('nodesVisited', 0),
							attrs=stats.get('attributesChecked', 0),
							scripts=stats.get('scriptsInspected', 0),
							duration=stats.get('durationMs', 0)
						)
					)
				
				if self.detailed_report and scan_results.get('vulnerabilities'):
					print_info("\n" + "=" * 80)
					print_info("DETAILED VULNERABILITY REPORT")
					print_info("=" * 80)
					
					for i, vuln in enumerate(scan_results.get('vulnerabilities', []), 1):
						print_info(f"\n[{i}] {vuln.get('type', 'Unknown')} - {vuln.get('severity', 'Unknown')} Severity")
						print_info(f"    Location: {vuln.get('location', 'Unknown')}")
						print_info(f"    Description: {vuln.get('description', 'No description')}")
						if vuln.get('code'):
							print_info(f"    Code: {vuln.get('code', '')[:150]}")
						if vuln.get('element'):
							element = vuln.get('element', {})
							if element.get('tagName'):
								print_info(f"    Element: <{element.get('tagName', '')}>")
								if element.get('id'):
									print_info(f"      ID: {element.get('id')}")
								if element.get('className'):
									print_info(f"      Class: {element.get('className')}")
					
					print_info("\n" + "=" * 80)
				
				store_js = f"window.ksXSSScanResults = {result};"
				self.send_js(store_js)
				
				return True
			except Exception as e:
				print_error(f"Failed to parse scan results: {e}")
				print_info(f"Raw result: {result[:500]}")
				return False
		else:
			print_error("Failed to run XSS DOM scan")
			return False

