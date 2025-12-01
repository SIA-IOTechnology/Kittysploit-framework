from core.framework.base_module import BaseModule
from core.output_handler import *

class File(BaseModule):

	def current_session(self, key=None):
		"""
		Get current session information.
		
		Args:
			key: Optional key to get specific session property (e.g., 'platform')
			
		Returns:
			dict: Session information if key is None, or specific value if key is provided
		"""
		# Try to get session from Post module's session_id
		if hasattr(self, 'session_id'):
			session_id_value = self.session_id.value if hasattr(self.session_id, 'value') else str(self.session_id)
			if session_id_value and self.framework:
				try:
					# Get session from session_manager
					if hasattr(self.framework, 'session_manager'):
						session = self.framework.session_manager.get_session(session_id_value)
						if session:
							# Build session info dict
							session_info = {
								'id': session.id,
								'host': session.host,
								'port': session.port,
								'type': session.session_type,
								'platform': 'windows' if 'windows' in session.session_type.lower() else 'linux'
							}
							
							# Try to detect platform from session type or data
							if session.data:
								if 'platform' in session.data:
									session_info['platform'] = session.data['platform']
								elif session.session_type == 'ssh':
									# SSH sessions are typically Linux/Unix
									session_info['platform'] = 'linux'
							
							# If key is provided, return specific value
							if key:
								return session_info.get(key, None)
							
							return session_info
				except Exception:
					pass
		
		# Default fallback
		default_info = {
			'platform': 'linux',
			'type': 'unknown',
			'id': None
		}
		
		if key:
			return default_info.get(key, None)
		
		return default_info

	def command_exists(self, cmd):
		""" Check if a command exists on the current system """
		try:
			if self.current_session('platform') == 'windows':
				result = self.cmd_exec(f"cmd /c where /q {cmd} & if not errorlevel 1 echo true")
				if result and 'true' in result:
					return True
			else:
				result = self.cmd_exec(f"command -v {cmd} && echo true")
				if result and 'true' in result:
					return True
		except Exception:
			pass
		return False
	
	def read_file(self, filename):
		""" Read a file and return its content """
		try:
			platform = self.current_session('platform')
			if platform == 'windows':
				result = self.cmd_exec(f'type {filename}')
				return result if result else ""
			
			# For Linux/Unix, try cat command
			if self.command_exists('cat'):
				result = self.cmd_exec(f'cat {filename}')
				return result if result else ""
			
			# Fallback: try to read file directly
			result = self.cmd_exec(f'cat {filename}')
			return result if result else ""
		except Exception as e:
			# Return empty string on any error
			return ""		

	def write_file(self, data, filename):
		""" Write data to a file """
		if self.current_session('platform') == 'windows':
			self.cmd_exec(f'echo | set /p "{data}" > "{filename}"')
		else:
			self.cmd_exec(f"printf '{data}' > {filename}")

	def upload_file(self, remotefile, localfile):
#		""" Upload a file to the target """
#		if self.current_session['platform'] == 'windows':
#			self.cmd_exec(f"cmd.exe /C copy \"{localfile}\" \"{remotefile}\"")
#		else:
#			self.cmd_exec(f"cp {localfile} {remotefile}")
		
		pass

	def chmod_x(self, filename):
		""" Set file to executable """
		if self.current_session('platform') == 'windows':
			self.cmd_exec(f"cmd.exe /C attrib +x \"{filename}\"")
		else:
			self.cmd_exec(f"chmod +x {filename}")
	
	def file_exist(self, filename):
		""" Check if a file exists """
		if self.current_session('platform') == 'windows':
			response = self.cmd_exec(f"cmd.exe /C IF exist \"{filename}\" ( echo true )")
			if response and response.strip() == "true":
				return True
			return False
		else:
			response = self.cmd_exec(f"test -f \"{filename}\" && echo true")
			if response and response.strip() == "true":
				return True
			return False
	
	def pwd(self):
		""" Print current working directory """
		if self.current_session('platform') == 'windows':
			return self.cmd_exec('cd')
		else:
			return self.cmd_exec('pwd')
	
	def directory(self):
		""" List files in the current directory """
		if self.current_session('platform') == 'windows':
			return self.cmd_exec('dir')
		else:
			return self.cmd_exec('ls')

	def file_rm(self, filename):
		if self.current_session('platform') == 'windows':
			return self.cmd_exec(f'rd /s /q "{filename}"')
		else:
			return self.cmd_exec(f'rm -f "{filename}"')