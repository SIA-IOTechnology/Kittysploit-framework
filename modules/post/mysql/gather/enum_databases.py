from kittysploit import *
from lib.protocols.mysql.mysql_client import MySQLClient

class Module(Post, MySQLClient):

	__info__ = {
		"name": "Enumerate MySQL Databases",
		"description": "Enumerate all databases, tables, and columns in MySQL",
		"author": "KittySploit Team",
		"session_type": SessionType.MYSQL,
	}	

	database = OptString("", "Specific database to enumerate (all if empty)", False)
	show_data = OptBool(False, "Show sample data from tables", False)

	def run(self):
		try:
			databases = self.list_databases()
			
			print_info(f"Found {len(databases)} databases:")
			print_info("=" * 80)
			
			for db_name in databases:
				if db_name in ['information_schema', 'performance_schema', 'mysql', 'sys'] and not self.database:
					continue
				
				if self.database and db_name != self.database:
					continue
				
				print_info(f"\n[*] Database: {db_name}")
				print_info("-" * 80)
				
				try:
					self.use_database(db_name)
					tables = self.list_tables()
					
					if tables:
						print_info(f"  Tables ({len(tables)}):")
						for table_name in tables:
							print_info(f"    - {table_name}")
							
							columns = self.describe_table(table_name)
							if columns:
								print_info(f"      Columns:")
								for col in columns:
									col_name = col.get('Field', '')
									col_type = col.get('Type', '')
									col_null = col.get('Null', '')
									col_key = col.get('Key', '')
									print_info(f"        {col_name} ({col_type}) {'NULL' if col_null == 'YES' else 'NOT NULL'} {'PRIMARY' if col_key == 'PRI' else ''}")
							
							if self.show_data:
								try:
									rows = self.execute_query(f"SELECT * FROM `{table_name}` LIMIT 5")
									if rows:
										print_info(f"      Sample data ({len(rows)} rows):")
										for i, row in enumerate(rows, 1):
											row_str = ', '.join([f"{k}={v}" for k, v in row.items()])
											print_info(f"        [{i}] {row_str}")
								except Exception as e:
									print_warning(f"      Could not read data: {e}")
					else:
						print_info("No tables found")
						
				except Exception as e:
					print_warning(f"Error accessing database {db_name}: {e}")
			
			return True
			
		except ProcedureError:
			raise
		except Exception as e:
			raise ProcedureError(FailureType.Unknown, f"Error enumerating databases: {e}")

