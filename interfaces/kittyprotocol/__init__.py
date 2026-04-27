#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import json
import os
import tempfile
from datetime import datetime
from io import BytesIO, StringIO
from typing import Any, Dict

from flask import Flask, Response, jsonify, render_template, request, send_file

try:
    from flask_cors import CORS
except Exception:
    CORS = None

try:
    from flask_socketio import SocketIO
except Exception:
    SocketIO = None

from .core import KittyProtocolAnalyzer
from kittysploit import print_error, print_info, print_success


def create_app(tool: KittyProtocolAnalyzer = None) -> Flask:
    app = Flask(__name__, template_folder="templates", static_folder="static")
    shared_img_dir = os.path.abspath(
        os.path.join(os.path.dirname(__file__), "..", "static", "img")
    )

    if CORS is not None:
        CORS(app)

    socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading") if SocketIO is not None else None
    app.config["socketio"] = socketio

    def _emit_live_snapshot(snapshot: Dict[str, Any]) -> None:
        if socketio is not None:
            socketio.emit("live_snapshot", snapshot, namespace="/ws")

    app.config["tool"] = tool or KittyProtocolAnalyzer(live_update_callback=_emit_live_snapshot)

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

    @app.get("/api/health")
    def health():
        tool = app.config["tool"]
        return jsonify(tool.health())

    @app.get("/api/interfaces")
    def interfaces():
        tool = app.config["tool"]
        result = tool.list_interfaces()
        return jsonify(result), 200

    @app.get("/api/decryption/config")
    def decryption_config_get():
        tool = app.config["tool"]
        return jsonify(tool.get_decryption_config()), 200

    @app.post("/api/decryption/config")
    def decryption_config_set():
        tool = app.config["tool"]
        data: Dict[str, Any] = request.get_json(silent=True) or {}
        result = tool.set_decryption_config(
            tls_keylog_path=data.get("tls_keylog_path"),
            persist_secrets=data.get("persist_secrets"),
        )
        status = 200 if "error" not in result else 400
        return jsonify(result), status

    @app.delete("/api/decryption/config")
    def decryption_config_clear():
        tool = app.config["tool"]
        return jsonify(tool.clear_decryption_config()), 200

    @app.get("/api/decryption/status")
    def decryption_status():
        tool = app.config["tool"]
        return jsonify(tool.get_decryption_status()), 200

    @app.post("/api/analyze")
    def analyze():
        tool = app.config["tool"]
        data: Dict[str, Any] = request.get_json(silent=True) or {}
        form_mode = bool(request.files) or request.content_type and "multipart/form-data" in str(request.content_type).lower()

        def _as_bool(value: Any) -> bool:
            if isinstance(value, bool):
                return value
            text = str(value or "").strip().lower()
            return text in {"1", "true", "yes", "on"}

        if form_mode:
            form = request.form or {}
            uploaded = request.files.get("pcap_file")
            if not uploaded or not getattr(uploaded, "filename", ""):
                return jsonify({"error": "Missing uploaded pcap file"}), 400
            suffix = os.path.splitext(str(uploaded.filename))[1] or ".pcap"
            fd, tmp_path = tempfile.mkstemp(prefix="kittyprotocol-upload-", suffix=suffix)
            os.close(fd)
            uploaded.save(tmp_path)
            pcap = tmp_path
            if not os.path.isfile(pcap) or os.path.getsize(pcap) < 24:
                try:
                    os.remove(pcap)
                except Exception:
                    pass
                return jsonify({"error": "Uploaded file is empty or too small to be a valid capture"}), 400
            data = {
                "display_filter": form.get("display_filter", ""),
                "protocol_filter": form.get("protocol_filter", ""),
                "severity_filter": form.get("severity_filter", ""),
                "host_filter": form.get("host_filter", ""),
                "port_filter": form.get("port_filter", ""),
                "search": form.get("search", ""),
                "flow_page": form.get("flow_page", 1),
                "flow_per_page": form.get("flow_per_page", 25),
                "finding_page": form.get("finding_page", 1),
                "finding_per_page": form.get("finding_per_page", 30),
                "suggestion_page": form.get("suggestion_page", 1),
                "suggestion_per_page": form.get("suggestion_per_page", 20),
            }
            display_filter = str(form.get("display_filter") or "").strip()
            protocol_filter = form.get("protocol_filter")
            max_packets = form.get("max_packets")
            include_raw = _as_bool(form.get("include_raw", False))
            bpf_filter = str(form.get("bpf_filter") or "").strip()
            enable_fts = _as_bool(form.get("enable_fts", False))
        else:
            pcap = str(data.get("pcap") or "").strip()
            display_filter = str(data.get("display_filter") or "").strip()
            protocol_filter = data.get("protocol_filter")
            max_packets = data.get("max_packets")
            include_raw = bool(data.get("include_raw", False))
            bpf_filter = str(data.get("bpf_filter") or "").strip()
            enable_fts = bool(data.get("enable_fts", False))

        if not pcap:
            return jsonify({"error": "Missing pcap path or uploaded file"}), 400

        try:
            result = tool.analyze_file(
                pcap=pcap,
                display_filter=display_filter or None,
                protocol_filter=protocol_filter,
                max_packets=max_packets,
                include_raw=include_raw,
                bpf_filter=bpf_filter or None,
                enable_fts=enable_fts,
            )
            if "error" not in result:
                result = tool.query_result(
                    result,
                    protocol_filter=data.get("protocol_filter"),
                    severity_filter=data.get("severity_filter"),
                    host_filter=data.get("host_filter"),
                    port_filter=data.get("port_filter"),
                    search=data.get("search"),
                    flow_page=data.get("flow_page", 1),
                    flow_per_page=data.get("flow_per_page", 25),
                    finding_page=data.get("finding_page", 1),
                    finding_per_page=data.get("finding_per_page", 30),
                    suggestion_page=data.get("suggestion_page", 1),
                    suggestion_per_page=data.get("suggestion_per_page", 20),
                )
            status = 200 if "error" not in result else 400
            return jsonify(result), status
        except Exception as exc:
            return jsonify({"error": str(exc)}), 500

    @app.post("/api/live/start")
    def live_start():
        tool = app.config["tool"]
        data: Dict[str, Any] = request.get_json(silent=True) or {}
        result = tool.start_live_capture(
            interface=str(data.get("interface") or "").strip(),
            display_filter=str(data.get("display_filter") or "").strip() or None,
            protocol_filter=data.get("protocol_filter"),
            max_packets=data.get("max_packets"),
            include_raw=bool(data.get("include_raw", False)),
            bpf_filter=str(data.get("bpf_filter") or "").strip() or None,
        )
        status = 200 if "error" not in result else 400
        return jsonify(result), status

    @app.post("/api/live/stop")
    def live_stop():
        tool = app.config["tool"]
        return jsonify(tool.stop_live_capture())

    @app.get("/api/live/status")
    def live_status():
        tool = app.config["tool"]
        return jsonify(tool.get_live_status())

    @app.get("/api/live/snapshot")
    def live_snapshot():
        tool = app.config["tool"]
        result = tool.get_live_snapshot()
        result = tool.query_result(
            result,
            protocol_filter=request.args.get("protocol_filter"),
            severity_filter=request.args.get("severity_filter"),
            host_filter=request.args.get("host_filter"),
            port_filter=request.args.get("port_filter"),
            search=request.args.get("search"),
            flow_page=request.args.get("flow_page", 1),
            flow_per_page=request.args.get("flow_per_page", 25),
            finding_page=request.args.get("finding_page", 1),
            finding_per_page=request.args.get("finding_per_page", 30),
            suggestion_page=request.args.get("suggestion_page", 1),
            suggestion_per_page=request.args.get("suggestion_per_page", 20),
        )
        return jsonify(result)

    @app.get("/api/protocols")
    def protocols():
        tool = app.config["tool"]
        snapshot = tool.get_live_snapshot()
        protocol_items = snapshot.get("protocols", [])
        names = [str(item.get("protocol", "")).upper() for item in protocol_items if item.get("protocol")]
        return jsonify({"protocols": names, "stats": protocol_items})

    @app.get("/api/recordings")
    def recordings():
        tool = app.config["tool"]
        return jsonify(tool.list_recordings())

    @app.post("/api/recordings/save")
    def save_recording():
        tool = app.config["tool"]
        data: Dict[str, Any] = request.get_json(silent=True) or {}
        source_type = "live" if tool.get_live_status().get("running") else ("offline" if tool.get_last_result().get("pcap") else "analysis")
        result = tool.save_recording(name=str(data.get("name") or "").strip() or None, source_type=source_type)
        status = 200 if "error" not in result else 400
        return jsonify(result), status

    @app.post("/api/recordings/<recording_id>/load")
    def load_recording(recording_id: str):
        tool = app.config["tool"]
        result = tool.load_recording(recording_id)
        status = 200 if "error" not in result else 404
        return jsonify(result), status

    @app.get("/api/recordings/<recording_id>/replay")
    def replay_recording(recording_id: str):
        tool = app.config["tool"]
        result = tool.replay_recording(
            recording_id,
            cursor=request.args.get("cursor", 0),
            limit=request.args.get("limit", 25),
            flow_id=request.args.get("flow_id"),
        )
        status = 200 if "error" not in result else 404
        return jsonify(result), status

    @app.get("/api/flows/<path:flow_id>/packets")
    def flow_packets_page(flow_id: str):
        tool = app.config["tool"]
        result = tool.get_flow_packets_page(
            flow_id,
            offset=request.args.get("offset", 0),
            limit=request.args.get("limit", 100),
        )
        status = 200 if "error" not in result else 404
        return jsonify(result), status

    @app.get("/api/flows/<path:flow_id>/packet/hex")
    def flow_packet_hex(flow_id: str):
        tool = app.config["tool"]
        raw_idx = request.args.get("flow_packet_index", "")
        try:
            idx = int(raw_idx)
        except (TypeError, ValueError):
            return jsonify({"error": "Parameter flow_packet_index (integer) is required"}), 400
        try:
            max_bytes = int(request.args.get("max_bytes", 8192))
        except (TypeError, ValueError):
            max_bytes = 8192
        result = tool.get_flow_packet_hex_from_pcap(flow_id, idx, max_bytes=max_bytes)
        status = 200 if "error" not in result else 400
        return jsonify(result), status

    @app.get("/api/flows/<path:flow_id>")
    def flow_detail(flow_id: str):
        tool = app.config["tool"]
        result = tool.get_flow_detail(flow_id)
        status = 200 if "error" not in result else 404
        return jsonify(result), status

    @app.post("/api/query")
    def query_last_result():
        tool = app.config["tool"]
        data: Dict[str, Any] = request.get_json(silent=True) or {}
        base = tool.get_live_snapshot() if tool.get_live_status().get("running") else tool.get_last_result()
        if not base:
            return jsonify({"error": "No analysis context available yet"}), 400
        result = tool.query_result(
            base,
            protocol_filter=data.get("protocol_filter"),
            severity_filter=data.get("severity_filter"),
            host_filter=data.get("host_filter"),
            port_filter=data.get("port_filter"),
            search=data.get("search"),
            flow_page=data.get("flow_page", 1),
            flow_per_page=data.get("flow_per_page", 25),
            finding_page=data.get("finding_page", 1),
            finding_per_page=data.get("finding_per_page", 30),
            suggestion_page=data.get("suggestion_page", 1),
            suggestion_per_page=data.get("suggestion_per_page", 20),
        )
        return jsonify(result), 200

    @app.post("/api/export")
    def export_report():
        tool = app.config["tool"]
        data: Dict[str, Any] = request.get_json(silent=True) or {}
        base = tool.get_live_snapshot() if tool.get_live_status().get("running") else tool.get_last_result()
        if not base:
            return jsonify({"error": "No analysis context available yet"}), 400
        result = tool.query_result(
            base,
            protocol_filter=data.get("protocol_filter"),
            severity_filter=data.get("severity_filter"),
            host_filter=data.get("host_filter"),
            port_filter=data.get("port_filter"),
            search=data.get("search"),
            flow_page=data.get("flow_page", 1),
            flow_per_page=data.get("flow_per_page", 200),
            finding_page=data.get("finding_page", 1),
            finding_per_page=data.get("finding_per_page", 200),
            suggestion_page=data.get("suggestion_page", 1),
            suggestion_per_page=data.get("suggestion_per_page", 200),
        )
        report_format = str(data.get("format") or "json").strip().lower()
        content = tool.build_report(result, report_format=report_format)
        if report_format == "html":
            return Response(
                content,
                mimetype="text/html",
                headers={"Content-Disposition": "attachment; filename=kittyprotocol-report.html"},
            )
        return Response(
            content,
            mimetype="application/json",
            headers={"Content-Disposition": "attachment; filename=kittyprotocol-report.json"},
        )

    @app.get("/api/docs/filters")
    def docs_filters():
        tool = app.config["tool"]
        return jsonify(tool.bpf_display_filter_help())

    @app.get("/api/iocs")
    def ioc_summary():
        tool = app.config["tool"]
        return jsonify(
            tool.get_ioc_summary(
                protocol_filter=request.args.get("protocol_filter"),
                host_filter=request.args.get("host_filter"),
            )
        )

    @app.get("/api/iocs/export")
    def ioc_export():
        tool = app.config["tool"]
        fmt = str(request.args.get("format") or "json").strip().lower()
        data = tool.get_ioc_summary(
            protocol_filter=request.args.get("protocol_filter"),
            host_filter=request.args.get("host_filter"),
        )
        if fmt == "csv":
            out = StringIO()
            out.write("kind,value,mitre\n")
            mitre = data.get("mitre_mapping", {}) or {}
            for kind, values in (data.get("iocs", {}) or {}).items():
                m = "|".join(str(x) for x in (mitre.get(kind) or []))
                for value in values or []:
                    out.write(f"{kind},{str(value).replace(',', ' ')},{m}\n")
            return Response(
                out.getvalue(),
                mimetype="text/csv",
                headers={"Content-Disposition": "attachment; filename=kittyprotocol-iocs.csv"},
            )
        return Response(
            json.dumps(data, ensure_ascii=False, indent=2),
            mimetype="application/json",
            headers={"Content-Disposition": "attachment; filename=kittyprotocol-iocs.json"},
        )

    @app.get("/api/case-bundle")
    def case_bundle():
        tool = app.config["tool"]
        base = tool.get_live_snapshot() if tool.get_live_status().get("running") else tool.get_last_result()
        if not base:
            return jsonify({"error": "No analysis context available yet"}), 400
        session_id = str(base.get("session_id") or "")
        annotations = tool.investigation.annotations_for_session(session_id) if session_id else []
        payload = {
            "session_id": session_id,
            "pcap": base.get("pcap", ""),
            "generated_at": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
            "summary": {
                "flow_count": base.get("flow_count", 0),
                "processed_packets": base.get("processed_packets", 0),
                "findings_count": len(base.get("patterns", []) or []),
            },
            "findings": base.get("patterns", []) or [],
            "annotations": annotations,
            "iocs": tool.get_ioc_summary().get("iocs", {}),
            "provenance": base.get("provenance", {}),
        }
        return jsonify(payload), 200

    @app.post("/api/compare")
    def compare_pcaps():
        data: Dict[str, Any] = request.get_json(silent=True) or {}
        pcap_a = str(data.get("pcap_a") or data.get("pcap_left") or "").strip()
        pcap_b = str(data.get("pcap_b") or data.get("pcap_right") or "").strip()
        if not pcap_a or not pcap_b:
            return jsonify({"error": "pcap_a and pcap_b are required"}), 400
        result = KittyProtocolAnalyzer.compare_pcaps(
            pcap_a,
            pcap_b,
            display_filter=str(data.get("display_filter") or "").strip() or None,
            protocol_filter=data.get("protocol_filter"),
            max_packets=data.get("max_packets", 2000),
            bpf_filter_a=str(data.get("bpf_filter_a") or "").strip() or None,
            bpf_filter_b=str(data.get("bpf_filter_b") or "").strip() or None,
            include_raw=bool(data.get("include_raw", False)),
            enable_fts=bool(data.get("enable_fts", False)),
        )
        status = 200 if "error" not in result else 400
        return jsonify(result), status

    @app.post("/api/search")
    def search_payloads_post():
        tool = app.config["tool"]
        data: Dict[str, Any] = request.get_json(silent=True) or {}
        q = str(data.get("q") or data.get("query") or "").strip()
        if not q:
            return jsonify({"error": "query required"}), 400
        return jsonify(tool.search_payloads(q, limit=int(data.get("limit", 80)))), 200

    @app.get("/api/search")
    def search_payloads_get():
        tool = app.config["tool"]
        q = str(request.args.get("q") or "").strip()
        if not q:
            return jsonify({"error": "query required"}), 400
        return jsonify(tool.search_payloads(q, limit=int(request.args.get("limit", 80)))), 200

    @app.get("/api/views")
    def list_views():
        tool = app.config["tool"]
        return jsonify(tool.investigation.list_views())

    @app.get("/api/views/<path:name>")
    def get_view(name: str):
        tool = app.config["tool"]
        return jsonify(tool.investigation.get_view(name))

    @app.post("/api/views")
    def save_view():
        tool = app.config["tool"]
        data: Dict[str, Any] = request.get_json(silent=True) or {}
        name = str(data.get("name") or "").strip()
        if not name:
            return jsonify({"error": "name required"}), 400
        return jsonify(
            tool.investigation.save_view(
                name=name,
                filters=dict(data.get("filters") or {}),
                description=str(data.get("description") or ""),
            )
        )

    @app.delete("/api/views/<path:name>")
    def delete_view(name: str):
        tool = app.config["tool"]
        return jsonify(tool.investigation.delete_view(name))

    @app.post("/api/annotations")
    def add_annotation():
        tool = app.config["tool"]
        data: Dict[str, Any] = request.get_json(silent=True) or {}
        sid = str(data.get("session_id") or "").strip() or str(tool.get_last_result().get("session_id") or "")
        flow_id = str(data.get("flow_id") or "").strip()
        note = str(data.get("note") or "").strip()
        if not sid or not flow_id or not note:
            return jsonify({"error": "session_id (or active analysis), flow_id and note are required"}), 400
        return jsonify(
            tool.investigation.add_annotation(
                session_id=sid,
                flow_id=flow_id,
                note=note,
                tags=data.get("tags"),
                ticket_url=str(data.get("ticket_url") or ""),
                status=str(data.get("status") or "to verify"),
                assignee=str(data.get("assignee") or ""),
            )
        )

    @app.get("/api/annotations")
    def list_annotations():
        tool = app.config["tool"]
        sid = request.args.get("session_id", "").strip()
        return jsonify(tool.investigation.list_annotations(session_id=sid or None))

    @app.get("/api/export/flow/<path:flow_id>.pcap")
    def export_flow_pcap(flow_id: str):
        tool = app.config["tool"]
        try:
            raw, fname = tool.export_flow_pcap_bytes(flow_id)
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400
        except RuntimeError as exc:
            return jsonify({"error": str(exc)}), 500
        return send_file(
            BytesIO(raw),
            mimetype="application/vnd.tcpdump.pcap",
            as_attachment=True,
            download_name=fname,
        )

    @app.get("/api/export/flow/<path:flow_id>.json")
    def export_flow_json(flow_id: str):
        tool = app.config["tool"]
        t0 = request.args.get("time_start")
        t1 = request.args.get("time_end")
        t0f = float(t0) if t0 not in (None, "") else None
        t1f = float(t1) if t1 not in (None, "") else None
        out = tool.export_flow_subset_json(flow_id, time_start=t0f, time_end=t1f)
        if "error" in out:
            return jsonify(out), 400
        return jsonify(out)

    @app.get("/api/playbook/<path:pattern_type>")
    def playbook(pattern_type: str):
        from .playbooks import get_playbook

        return jsonify(get_playbook(pattern_type))

    return app


def _run_cli_scan(
    pcap: str,
    display_filter: str = "",
    protocol_filter: str = "",
    max_packets: int = 2000,
    include_raw: bool = False,
) -> int:
    tool = KittyProtocolAnalyzer()
    result = tool.analyze_file(
        pcap=pcap,
        display_filter=display_filter or None,
        protocol_filter=protocol_filter or "",
        max_packets=max_packets,
        include_raw=include_raw,
    )
    if "error" in result:
        print_error(result["error"])
        return 1
    print_success(f"Analysis complete for {pcap}")
    print_info(f"Flows: {result.get('flow_count', 0)} | Patterns: {len(result.get('patterns', []))}")
    return 0


def main() -> None:
    parser = argparse.ArgumentParser(
        description="KittyProtocol Interface",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python kittyprotocol.py\n"
            "  python kittyprotocol.py --port 8004\n"
            "  python kittyprotocol.py capture.pcapng\n"
            "  python kittyprotocol.py capture.pcap --display-filter http\n"
            "  python kittyprotocol.py capture.pcap --protocol-filter http,dns\n"
        ),
    )
    parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="API bind address (default: 127.0.0.1). Use 0.0.0.0 for all interfaces; 'any' is accepted as alias for 0.0.0.0.",
    )
    parser.add_argument("--port", type=int, default=8004, help="API port (default: 8004)")
    parser.add_argument("--display-filter", dest="display_filter", default="", help="Optional Wireshark display filter")
    parser.add_argument("--protocol-filter", dest="protocol_filter", default="", help="Comma-separated protocols (e.g. http,dns,mqtt)")
    parser.add_argument("--max-packets", dest="max_packets", type=int, default=2000, help="Max packets to inspect")
    parser.add_argument("--include-raw", action="store_true", help="Include raw excerpts in JSON output")
    parser.add_argument("pcap", nargs="?", help="PCAP/PCAPNG file to analyze in CLI mode")
    args = parser.parse_args()

    bind_host = str(args.host or "").strip().lower()
    if bind_host in {"any", "all", "*"}:
        args.host = "0.0.0.0"

    if args.pcap:
        raise SystemExit(
            _run_cli_scan(args.pcap, args.display_filter, args.protocol_filter, args.max_packets, args.include_raw)
        )

    tool = KittyProtocolAnalyzer()
    app_instance = create_app(tool=tool)
    socketio = app_instance.config.get("socketio")
    print_success(f"Starting KittyProtocol on http://{args.host}:{args.port}")
    if socketio is not None:
        socketio.run(
            app_instance,
            host=args.host,
            port=args.port,
            debug=False,
            use_reloader=False,
            allow_unsafe_werkzeug=True,
        )
    else:
        app_instance.run(host=args.host, port=args.port, debug=False, use_reloader=False, threaded=True)


if __name__ == "__main__":
    main()
