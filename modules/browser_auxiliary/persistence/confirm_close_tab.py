from kittysploit import *

class Module(BrowserAuxiliary):

	__info__ = {
		"name": "Pop-Under Tab Closing",
		"description": "Create a pop-under window on user's tab closing",
		"author": "KittySploit Team",
		"browser": Browser.ALL,
		"platform": Platform.ALL,
		"session_type": SessionType.BROWSER,
	}	
	

	def run(self):
		js_code = """
let preventExit = false;

// Exemple : champ de formulaire qui déclenche l'avertissement
document.querySelectorAll("input, textarea, select").forEach((element) => {
    element.addEventListener("change", () => {
        preventExit = true;
    });
});

// Suppress warning after save
function saveData() {
    preventExit = false;
}

// Le vrai beforeunload conforme aux navigateurs modernes
window.addEventListener("beforeunload", (event) => {
    if (!preventExit) return;
    event.preventDefault();
    event.returnValue = "";
});
"""
		return self.send_js(js_code)
