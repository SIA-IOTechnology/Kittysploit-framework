from kittysploit import *
import json


class Module(BrowserAuxiliary):

	__info__ = {
		"name": "Web Device APIs Probe",
		"description": "Probe WebUSB, WebSerial and WebBluetooth availability and optionally request devices",
		"author": "KittySploit Team",
		"browser": Browser.ALL,
		"platform": Platform.ALL,
		"session_type": SessionType.BROWSER,
	}

	request_devices = OptBool(
		False,
		"Call requestDevice/requestPort (requires user gesture; may show browser picker)",
		False,
	)
	include_hid = OptBool(True, "Also probe WebHID availability", False)

	def run(self):
		request_devices = self._to_bool(self.request_devices)
		include_hid = self._to_bool(self.include_hid)

		code_js = f"""
		(function() {{
			const REQUEST = {str(request_devices).lower()};
			const INCLUDE_HID = {str(include_hid).lower()};

			const out = {{
				ok: true,
				origin: location.origin,
				page_url: location.href,
				secure_context: !!window.isSecureContext,
				usb: {{ supported: !!(navigator.usb) }},
				serial: {{ supported: !!(navigator.serial) }},
				bluetooth: {{ supported: !!(navigator.bluetooth) }},
				hid: {{ supported: !!(navigator.hid) }},
				notes: []
			}};

			function mapUsbDevice(d) {{
				return {{
					vendorId: d.vendorId,
					productId: d.productId,
					productName: d.productName || null,
					manufacturerName: d.manufacturerName || null,
					serialNumber: d.serialNumber || null,
					opened: !!d.opened
				}};
			}}
			function mapSerialPort(p) {{
				const info = (p.getInfo && p.getInfo()) || {{}};
				return {{
					usbVendorId: info.usbVendorId || null,
					usbProductId: info.usbProductId || null
				}};
			}}
			function mapHidDevice(d) {{
				return {{
					vendorId: d.vendorId,
					productId: d.productId,
					productName: d.productName || null,
					opened: !!d.opened
				}};
			}}

			const tasks = [];

			if (navigator.usb) {{
				tasks.push(
					navigator.usb.getDevices()
						.then(function(devs) {{
							out.usb.getDevices = (devs || []).map(mapUsbDevice);
						}})
						.catch(function(e) {{
							out.usb.getDevices_error = e.message || String(e);
						}})
				);
				if (REQUEST) {{
					tasks.push(
						navigator.usb.requestDevice({{ filters: [] }})
							.then(function(d) {{ out.usb.requested = mapUsbDevice(d); }})
							.catch(function(e) {{ out.usb.request_error = e.message || String(e); }})
					);
				}}
			}} else {{
				out.notes.push('WebUSB unavailable');
			}}

			if (navigator.serial) {{
				tasks.push(
					navigator.serial.getPorts()
						.then(function(ports) {{
							out.serial.getPorts = (ports || []).map(mapSerialPort);
						}})
						.catch(function(e) {{
							out.serial.getPorts_error = e.message || String(e);
						}})
				);
				if (REQUEST) {{
					tasks.push(
						navigator.serial.requestPort({{}})
							.then(function(p) {{ out.serial.requested = mapSerialPort(p); }})
							.catch(function(e) {{ out.serial.request_error = e.message || String(e); }})
					);
				}}
			}} else {{
				out.notes.push('WebSerial unavailable');
			}}

			if (navigator.bluetooth) {{
				out.bluetooth.getAvailability = null;
				if (typeof navigator.bluetooth.getAvailability === 'function') {{
					tasks.push(
						navigator.bluetooth.getAvailability()
							.then(function(v) {{ out.bluetooth.getAvailability = !!v; }})
							.catch(function(e) {{ out.bluetooth.availability_error = e.message || String(e); }})
					);
				}}
				if (typeof navigator.bluetooth.getDevices === 'function') {{
					tasks.push(
						navigator.bluetooth.getDevices()
							.then(function(devs) {{
								out.bluetooth.getDevices = (devs || []).map(function(d) {{
									return {{ id: d.id || null, name: d.name || null }};
								}});
							}})
							.catch(function(e) {{
								out.bluetooth.getDevices_error = e.message || String(e);
							}})
					);
				}}
				if (REQUEST && typeof navigator.bluetooth.requestDevice === 'function') {{
					tasks.push(
						navigator.bluetooth.requestDevice({{
							acceptAllDevices: true,
							optionalServices: ['battery_service', 'device_information']
						}})
							.then(function(d) {{
								out.bluetooth.requested = {{ id: d.id || null, name: d.name || null }};
							}})
							.catch(function(e) {{
								out.bluetooth.request_error = e.message || String(e);
							}})
					);
				}}
			}} else {{
				out.notes.push('WebBluetooth unavailable');
			}}

			if (INCLUDE_HID) {{
				if (navigator.hid) {{
					tasks.push(
						navigator.hid.getDevices()
							.then(function(devs) {{
								out.hid.getDevices = (devs || []).map(mapHidDevice);
							}})
							.catch(function(e) {{
								out.hid.getDevices_error = e.message || String(e);
							}})
					);
					if (REQUEST) {{
						tasks.push(
							navigator.hid.requestDevice({{ filters: [] }})
								.then(function(devs) {{
									out.hid.requested = (devs || []).map(mapHidDevice);
								}})
								.catch(function(e) {{
									out.hid.request_error = e.message || String(e);
								}})
						);
					}}
				}} else {{
					out.notes.push('WebHID unavailable');
				}}
			}}

			if (!window.isSecureContext) {{
				out.notes.push('Device APIs generally require a secure context (HTTPS/localhost)');
			}}
			if (REQUEST) {{
				out.notes.push('request_* calls need a transient user gesture; may fail silently without one');
			}}

			return Promise.all(tasks).then(function() {{
				return JSON.stringify(out);
			}});
		}})();
		"""

		result = self.send_js_and_wait_for_response(code_js, timeout=25.0)
		if not result:
			print_error("Failed to run device APIs probe")
			return False
		if isinstance(result, str) and result.startswith("Error:"):
			print_error(result)
			return False

		try:
			data = json.loads(result)
		except json.JSONDecodeError as exc:
			print_error(f"Failed to parse response: {exc}")
			return False

		print_info("=" * 60)
		print_info("Web Device APIs Probe")
		print_info(f"  Page: {data.get('page_url')}")
		print_info(f"  Secure context: {data.get('secure_context')}")

		for key in ("usb", "serial", "bluetooth", "hid"):
			section = data.get(key) or {}
			if not section:
				continue
			supported = section.get("supported")
			print_info("-" * 60)
			print_info(f"  {key.upper()}: supported={supported}")
			for k, v in section.items():
				if k == "supported":
					continue
				if v in (None, [], {}):
					continue
				printer = print_warning if "request" in k or k.startswith("get") else print_info
				printer(f"    {k}: {json.dumps(v, ensure_ascii=False)}")

		for note in data.get("notes") or []:
			print_info(f"  Note: {note}")
		return True
