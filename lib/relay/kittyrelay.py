#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
KittyRelay — standalone P2P rendezvous hub (stdlib only).

Run on a reachable host without the KittySploit framework. Operators and agents
pair by room token; KittySploit connects with listeners/multi/p2p_relay role=operator.

Examples:
  kittyrelay --port 9000
  python -m lib.relay --host 0.0.0.0 --port 9000
  python scripts/kittyrelay.py --port 9000
"""

from __future__ import annotations

import argparse
import signal
import sys
import time

from lib.relay.p2p_relay_core import RelayHub

BANNER = """\
KittyRelay — rendezvous hub (no framework required)
Pair agents and operators with the same room token (KSRL:v1|v2:ROLE:TOKEN).
v2 peers may use E2E encryption (KSF1) after pairing — hub sees opaque bytes.
Operator side: kittysploit → use listeners/multi/p2p_relay → set role operator
"""


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="kittyrelay",
        description="Standalone KittySploit relay hub for NAT-friendly C2 rendezvous.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Workflow:\n"
            "  1. Start this hub on a reachable host (VPS, edge box, etc.).\n"
            "  2. Deploy a p2p relay agent payload on the target.\n"
            "  3. In KittySploit: use listeners/multi/p2p_relay, role=operator, same token.\n"
        ),
    )
    parser.add_argument(
        "--host",
        default="0.0.0.0",
        help="Bind address (default: 0.0.0.0)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=9000,
        help="Listen port (default: 9000)",
    )
    parser.add_argument(
        "--status-interval",
        type=int,
        default=30,
        help="Seconds between pending-room status lines; 0 disables (default: 30)",
    )
    parser.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        help="Minimal logging",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    hub = RelayHub(args.host, args.port)

    def _shutdown(_signum=None, _frame=None) -> None:
        if not args.quiet:
            print("\n[kittyrelay] stopping...", file=sys.stderr)
        hub.stop()
        raise SystemExit(0)

    signal.signal(signal.SIGINT, _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)

    try:
        hub.start()
    except OSError as exc:
        print(f"[kittyrelay] failed to bind {args.host}:{args.port}: {exc}", file=sys.stderr)
        return 1

    if not args.quiet:
        print(BANNER, end="")
        print(f"[kittyrelay] listening on {args.host}:{args.port}")
        print("[kittyrelay] Ctrl+C to stop")

    last_status = 0.0
    try:
        while hub.running:
            time.sleep(1)
            if args.quiet or args.status_interval <= 0:
                continue
            now = time.time()
            if now - last_status < args.status_interval:
                continue
            last_status = now
            pending = hub.pending_counts()
            if not pending:
                continue
            for token, counts in pending.items():
                print(
                    f"[kittyrelay] room '{token}': "
                    f"{counts['agents']} agent(s), {counts['operators']} operator(s) waiting",
                    file=sys.stderr,
                )
    except KeyboardInterrupt:
        _shutdown()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
