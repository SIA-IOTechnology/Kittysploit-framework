from lib.post.windows.registry import Registry
from core.output_handler import *

class Priv(Registry):

	SYSTEM_SID = 'S-1-5-18'
	ADMINISTRATORS_SID = 'S-1-5-32-544'

	def is_admin(self):
		local_service_key = self.registry_enumkeys('HKU\S-1-5-19')
		if local_service_key:
			return True
		return False
	
	def is_uac_enabled(self):
		enable_lua = self.registry_getvaldata('HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System','EnableLUA')
		if enable_lua:
			return True
		return False
	
	def get_whoami(self):
		whoami = self.cmd_exec('/c whoami /groups')
		if whoami:
			if "Access is denied" in whoami:
				return False
			else:
				return whoami
		return False
	
	def is_in_admin_group(self):
		whoami = self.get_whoami()
		if ADMINISTRATORS_SID in whoami:
			return True
		else:
			return False

	def is_system(self):
		rep = self.registry_enumkeys('HKLM\SAM\SAM')
		if rep:
			return True
		return False

	def get_uac_level(self):
		uac_level = self.registry_getvaldata('HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System', 'ConsentPromptBehaviorAdmin')
		if uac_level:
			return uac_level
		return
