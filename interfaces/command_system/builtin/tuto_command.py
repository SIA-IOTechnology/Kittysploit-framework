#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Tuto command: display usage explanations in English for each module type.
"""

from interfaces.command_system.base_command import BaseCommand
from core.output_handler import print_info, print_status, print_success, print_table


# English explanations for each module type (short summary + detailed text)
MODULE_TYPE_TUTORIALS = {
    "exploits": {
        "summary": "Vulnerability exploitation modules that deliver payloads to targets.",
        "detail": """
Exploits are modules that leverage known or discovered vulnerabilities to execute code on a target system.

  How to use:
  1. use <exploit_path>       e.g. use exploits/http/my_exploit
  2. show options              Display and set required options (rhost, rport, payload, etc.)
  3. set payload <path>        Choose a payload (use compatible_payloads to list compatible ones)
  4. set rhost / rport         Set target host and port
  5. set obfuscator <path>     (optional) Same obfuscator for listener and payload (e.g. obfuscators/python/stream/xor); set key if needed
  6. run                       Execute the exploit

  Tips:
  - Use 'check' to test if the target is vulnerable without attacking.
  - For reverse shells, the exploit can start a listener automatically; if you set obfuscator on the exploit, it is applied to both the listener and the payload when you run.
  - Required options are marked; use 'show options' and set all required fields.
""",
    },
    "auxiliary": {
        "summary": "Support modules: scanning, fuzzing, info gathering, denial-of-service.",
        "detail": """
Auxiliary modules perform supporting tasks: scanning, fuzzing, information gathering, or denial-of-service. They do not typically open a shell by themselves.

  How to use:
  1. use <auxiliary_path>      e.g. use auxiliary/server/honeypot_ftp
  2. show options              Set module options (hosts, ports, timeouts, etc.)
  3. set <option> <value>      Configure the module
  4. run                       Execute the auxiliary module

  Tips:
  - Many auxiliary modules are servers (e.g. honeypots, callbacks); they run until stopped.
  - Use 'show options' to see required vs optional parameters.
""",
    },
    "payloads": {
        "summary": "Code that runs on the target after a successful exploit (e.g. shell, meterpreter).",
        "detail": """
Payloads are the code delivered and executed on the target after a successful exploit (e.g. reverse shell, Meterpreter stager).

  How to use:
  1. Payloads are selected via the 'set payload <path>' option when using an exploit.
  2. use <exploit_path> or use <payload_path> to generate a standalone payload
  3. show payloads or compatible_payloads   List payloads compatible with the current exploit
  4. set payload <payload_path>             e.g. set payload payloads/singles/cmd/unix/bash_reverse_tcp
  5. set LHOST / LPORT (and any payload-specific options)
  6. If your LISTENER uses an obfuscator: set obfuscator <same path> and set the same options (e.g. key) on the payload, then generate/run
  7. run or generate

  Tips:
  - For reverse payloads, start a listener (use a listener module, set options, run) before running the exploit.
  - If the listener has obfuscator set (e.g. obfuscators/python/stream/xor with key 'mykey'), you must set the same obfuscator and key on the payload when generating, so both sides encode/decode the C2 stream the same way.
  - Staged payloads use a small stager that fetches the rest; single payloads are self-contained.
""",
    },
    "encoders": {
        "summary": "Encode payloads to evade signature-based detection (e.g. antivirus).",
        "detail": """
Encoders transform payloads (e.g. base64, XOR) to evade signature-based detection. They are often used as an option on an exploit or payload.

  How to use:
  1. When using an exploit, set the encoder option if the module supports it:
     set encoder encoders/cmd/base64
  2. Configure encoder-specific options (e.g. iterations, alphabet) via show options / set.

  Tips:
  - Encoding can reduce detection but may increase size or require a compatible decoder on the target.
  - Use 'show encoders' to list available encoders.
""",
    },
    "obfuscators": {
        "summary": "Obfuscate C2 traffic between the listener and the target (encode/decode stream).",
        "detail": """
Obfuscators apply encode/decode to the communication stream between the framework listener and the target, making traffic harder to detect or analyze.

  How to use:
  1. On the LISTENER: use <listener_path>, then set obfuscator <path> (e.g. obfuscators/python/stream/xor), set key and other obfuscator options, set lhost/lport, run.
  2. On the PAYLOAD: when generating the payload (use <payload>, set lhost/lport), set the SAME obfuscator and SAME options (e.g. key) as the listener, then generate/run.

  Important:
  - If the listener uses an obfuscator, the generated payload MUST use the same obfuscator and same options (e.g. XOR key). Otherwise the C2 channel will not work (both sides must encode/decode the same way).
  - Compatibility: each obfuscator declares which payload client languages it supports (e.g. python, powershell). Each payload declares its client language. Only compatible obfuscator+payload pairs work; if you set an incompatible obfuscator on a payload, generation will warn and produce a non-obfuscated payload. Use 'show info' on an obfuscator to see "Compatible with payloads (client language): ...".
  - Use 'show obfuscators' to list available obfuscator modules.
""",
    },
    "listeners": {
        "summary": "Receive connections from exploited targets (reverse shells, callbacks).",
        "detail": """
Listeners wait for incoming connections from exploited targets (e.g. reverse shells, Meterpreter callbacks). You must start a listener before running a reverse exploit.

  How to use:
  1. use <listener_path>       e.g. use listeners/multi/reverse_tcp
  2. show options              Set LHOST, LPORT, payload (if applicable), obfuscator (optional)
  3. set lhost <your_ip>
  4. set lport <port>
  5. run                       Start the listener; use 'sessions' to see new sessions

  Tips:
  - Match the listener type and port to the payload (e.g. reverse_tcp payload needs a reverse_tcp listener).
  - Optional 'obfuscator' option can encode the C2 stream; set it before run.
""",
    },
    "post": {
        "summary": "Post-exploitation modules run inside an existing session (gather, pivot, persistence).",
        "detail": """
Post-exploitation (post) modules run in the context of an existing session to gather data, pivot, install persistence, or manage the compromised system.

  How to use:
  1. Open a session: sessions interact <session_id> (or use 'run' from an exploit and get a session)
  2. use <post_module_path>   e.g. use post/shell/linux/gather/enum_users
  3. show options              Set session/target options (often SESSION or session_id)
  4. set session <id>          If the module requires a session
  5. run                       Execute the post module

  Tips:
  - Many post modules require a session (shell or meterpreter); set the session option to the active session ID.
  - Use 'show post' or browse post/ to find gather, exploit, pivot, or persistence modules.
""",
    },
    "scanner": {
        "summary": "Modules that scan or probe targets for vulnerabilities or services.",
        "detail": """
Scanner modules probe targets (hosts, ports, services) to find vulnerabilities or misconfigurations. They can be used standalone or to support exploit selection.

  How to use:
  1. use <scanner_path>        e.g. use scanner/alchemycms_eval_rce
  2. show options              Set target (rhost, rport, threads, etc.)
  3. set rhost <target>
  4. run                       Run the scan

  Tips:
  - Use 'scanner' command or 'use' with a path under scanner/ to run scan modules.
""",
    },
    "workflow": {
        "summary": "Automate sequences of modules (e.g. scan then exploit).",
        "detail": """
Workflow modules chain multiple steps (e.g. scan then exploit) into a single run. They automate common attack sequences.

  How to use:
  1. use <workflow_path>       e.g. use workflow/simple_workflow
  2. show options              Configure workflow targets and steps
  3. set options as required by the workflow
  4. run                       Execute the workflow

  Tips:
  - Options depend on the workflow; check show options and the module description.
""",
    },
    "backdoors": {
        "summary": "Modules that install or use backdoors (e.g. web shells, persistent access).",
        "detail": """
Backdoor modules provide or install persistent access (e.g. web shells, custom backdoors). They are often used after initial access or with specific services.

  How to use:
  1. use <backdoor_path>       e.g. use backdoors/php/php_get
  2. show options              Set target (url, credentials, etc.)
  3. set required options
  4. run                       Deploy or use the backdoor

  Tips:
  - Backdoors may require a prior exploit or upload step; read the module info.
""",
    },
    "browser_exploits": {
        "summary": "Exploits that run in a browser context (client-side, e.g. fake captcha).",
        "detail": """
Browser exploits run in the context of a victim's browser (client-side). They often rely on social engineering (e.g. fake CAPTCHA, malicious page) to get the user to open a URL.

  How to use:
  1. use <browser_exploit_path>   e.g. use browser_exploits/misc/fake_captcha_reverse_shell
  2. show options                  Set SRVHOST, SRVPORT, payload, etc.
  3. Start a listener if the payload is reverse (e.g. reverse_tcp)
  4. run                            Serve the page; share the URL with the target
  5. When the target loads the page and triggers the flow, a session is created

  Tips:
  - Use with browser_server or a dedicated server; ensure LHOST/LPORT match your listener.
""",
    },
    "browser_auxiliary": {
        "summary": "Browser-based support modules (keyloggers, harvest, redirect, XSS).",
        "detail": """
Browser auxiliary modules perform support actions in the browser: keylogging, credential harvesting, redirects, XSS, etc. They require an active browser session (e.g. from browser_server).

  How to use:
  1. Establish a browser session (e.g. via browser_server and a hooked page).
  2. use <browser_auxiliary_path>   e.g. use browser_auxiliary/misc/keylogger
  3. show options                    Set session or target browser
  4. set session <browser_session_id>  if required
  5. run                              Execute the module in the context of the browser session

  Tips:
  - Session here usually refers to a browser session ID from the framework.
""",
    },
    "docker_environment": {
        "summary": "Pre-built Docker environments for exercises or lab targets.",
        "detail": """
Docker environment modules define or launch containerized targets (e.g. vulnerable apps) for practice or demos.

  How to use:
  1. use <docker_env_path>     e.g. use docker_environments/some_vuln_app
  2. show options              Set image, ports, etc.
  3. run                       Start or manage the environment (start/stop/status depends on the module)

  Tips:
  - Requires Docker; use 'environments' command to list and manage environments.
""",
    },
    "shortcut": {
        "summary": "Shortcuts to common workflows or one-shot tasks.",
        "detail": """
Shortcut modules wrap common workflows or one-shot tasks into a single entry point for convenience.

  How to use:
  1. use <shortcut_path>       e.g. use shortcut/example_shortcut
  2. show options
  3. set options as needed
  4. run                       Execute the shortcut

  Tips:
  - Use 'show shortcut' to list available shortcuts.
""",
    },
    "plugins": {
        "summary": "Framework extensions that add commands or features.",
        "detail": """
Plugins extend the framework with new commands or features (e.g. new scanners, integrations). They are loaded by the framework and may add commands to the CLI.

  How to use:
  - Plugins are typically loaded at startup or via the 'plugin' command (load/unload/list).
  - Once loaded, new commands or options appear; refer to each plugin's documentation.

  Tips:
  - Use 'plugin' command to list, load, or unload plugins.
""",
    },
}


class TutoCommand(BaseCommand):
    """Command to display usage tutorials (in English) for each module type."""

    @property
    def name(self) -> str:
        return "tuto"

    @property
    def description(self) -> str:
        return "Display usage explanations in English for each module type"

    @property
    def usage(self) -> str:
        return "tuto [module_type]"

    def execute(self, args, **kwargs) -> bool:
        if not args:
            self._show_all_types()
            return True
        module_type = args[0].strip().lower()
        if module_type in MODULE_TYPE_TUTORIALS:
            self._show_type_detail(module_type)
            return True
        # Fuzzy match
        for key in MODULE_TYPE_TUTORIALS:
            if module_type in key or key.startswith(module_type):
                self._show_type_detail(key)
                return True
        self._show_all_types()
        print_info("")
        print_status(f"Unknown type '{args[0]}'. Use one of the types listed above with: tuto <type>")
        return True

    def _show_all_types(self):
        print_info("")
        print_success("Module types – usage tutorials (English)")
        print_info("")
        headers = ["Type", "Description"]
        rows = [
            (mtype, data["summary"].strip().replace("\n", " "))
            for mtype, data in MODULE_TYPE_TUTORIALS.items()
        ]
        print_table(headers, rows, max_width=100)
        print_info("")
        print_status("Usage: tuto <module_type>  – e.g. tuto exploits, tuto listeners")
        print_info("")

    def _show_type_detail(self, module_type: str):
        data = MODULE_TYPE_TUTORIALS[module_type]
        print_info("")
        print_success(f"  {module_type}")
        print_info("  " + "=" * 58)
        print_info("")
        print_status("  " + data["summary"].strip())
        print_info("")
        print_info(data["detail"].strip())
        print_info("")
        print_info("-" * 60)
        print_info("")
