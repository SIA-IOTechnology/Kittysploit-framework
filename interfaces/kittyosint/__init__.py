"""
KittyOSINT - Flask API & Main Entry
"""

import argparse
import os
from typing import Any, Dict, Optional

from flask import Flask, jsonify, render_template, request, send_file

try:
    from flask_cors import CORS
except Exception:
    CORS = None

from .core import KittyOSINT
from kittysploit import Framework, print_error, print_info, print_success, print_warning


def create_app(tool: KittyOSINT = None) -> Flask:
    app = Flask(__name__, template_folder="templates")
    shared_img_dir = os.path.abspath(
        os.path.join(os.path.dirname(__file__), "..", "static", "img")
    )

    if CORS is not None:
        CORS(app)

    app.config["tool"] = tool

    @app.get("/")
    def ui() -> str:
        return render_template("index.html")

    @app.get("/logo.png")
    def logo():
        logo_path = os.path.join(shared_img_dir, "logo.png")
        if os.path.exists(logo_path):
            return send_file(logo_path, mimetype="image/png")
        return ("Logo not found", 404)

    @app.get("/favicon.ico")
    def favicon():
        favicon_path = os.path.join(shared_img_dir, "favicon.ico")
        if os.path.exists(favicon_path):
            return send_file(favicon_path, mimetype="image/x-icon")
        return ("Favicon not found", 404)

    @app.get("/api/modules")
    def list_modules():
        tool: KittyOSINT = app.config["tool"]
        if tool is None:
            return jsonify({"error": "KittyOSINT not initialized"}), 503
        result = []
        for k, m in tool.modules.items():
            info = tool._module_info(m)
            result.append(
                {
                    "id": k,
                    "name": info.get("Name"),
                    "desc": info.get("Description"),
                    "type": info.get("Type", "core"),
                    "icon": info.get("Icon", ""),
                }
            )
        return jsonify(result)

    @app.post("/api/transform")
    def run_transform():
        tool: KittyOSINT = app.config["tool"]
        if tool is None:
            return jsonify({"error": "KittyOSINT not initialized"}), 503
        data: Dict[str, Any] = request.get_json(silent=True) or {}
        module_id = data.get("module")
        target = data.get("target")

        if not module_id or not target:
            return jsonify({"error": "Missing module or target"}), 400

        return jsonify(tool.execute_module(module_id, target))

    return app


app = create_app()


def _init_framework_for_osint() -> Optional[Framework]:
    try:
        framework = Framework(clean_sessions=False)
    except Exception as e:
        print_error(f"Error initializing framework: {e}")
        return None

    # Keep startup consistent with kittyproxy/kittyconsole.
    if not framework.check_charter_acceptance():
        print_info("First startup of KittySploit")
        if not framework.prompt_charter_acceptance():
            print_error("Charter not accepted. Stopping KittyOSINT startup.")
            return None

    if not framework.is_encryption_initialized():
        print_info("Setting up encryption for sensitive data protection...")
        if not framework.initialize_encryption():
            print_error("Failed to initialize encryption. Stopping KittyOSINT.")
            return None
    else:
        # Prompts for master key and unlocks encrypted DB fields.
        if not framework.load_encryption():
            print_error("Failed to load encryption. Database remains locked. Stopping KittyOSINT.")
            return None

    # Explicitly ensure DB schema/workspace are initialized for existing installations.
    try:
        workspace_name = framework.get_current_workspace_name()
        framework.db_manager.init_workspace_db(workspace_name)
        framework.db_manager.migrate_modules_table_constraint(workspace_name)
    except Exception as migration_error:
        print_warning(f"Could not run full DB migration checks: {migration_error}")

    return framework


def _run_cli_scan(target: str) -> None:
    print_info(f"Target: {target}")
    framework = _init_framework_for_osint()
    if framework is None:
        return
    cli_tool = KittyOSINT(framework=framework)
    for mod_id in cli_tool.modules:
        print_info(f"Running transform: {mod_id}...")
        res = cli_tool.execute_module(mod_id, target)
        if "error" not in res:
            print_success(" -> Execution complete")
        else:
            print_error(f" -> {res['error']}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="KittyOSINT Interface",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python kittyosint.py\n"
            "  python kittyosint.py --api-port 8003\n"
            "  python kittyosint.py --api-host 0.0.0.0 --api-port 8003\n"
            "  python kittyosint.py kittysploit.com"
        ),
    )
    parser.add_argument(
        "--host",
        "--api-host",
        dest="host",
        default="127.0.0.1",
        help="API host bind (default: 127.0.0.1)",
    )
    parser.add_argument(
        "--port",
        "--api-port",
        dest="port",
        type=int,
        default=8001,
        help="API port (default: 8001)",
    )
    parser.add_argument("--gui", action="store_true", help="Deprecated: GUI starts by default")
    parser.add_argument("target", nargs="?", help="Target domain for CLI scan")
    args = parser.parse_args()

    # Default behavior is now GUI for consistency with other interfaces.
    if args.target and not args.gui:
        _run_cli_scan(args.target)
        return

    framework = _init_framework_for_osint()
    if framework is None:
        return

    tool = KittyOSINT(framework=framework)
    app_instance = create_app(tool=tool)

    print_success(f"Starting Graph Interface on http://{args.host}:{args.port}")
    app_instance.run(host=args.host, port=args.port, debug=False, use_reloader=False, threaded=True)


if __name__ == "__main__":
    main()
