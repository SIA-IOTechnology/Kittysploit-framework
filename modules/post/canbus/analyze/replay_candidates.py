#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
CANBUS Replay Candidates - Ranks captured CAN frames as replay-attack candidates
Author: KittySploit Team
Version: 1.0.0
"""

from kittysploit import *
from core.output_handler import print_info, print_success, print_error, print_warning, print_status
from collections import defaultdict
from datetime import datetime
import json
import statistics


class Module(Post):
    """Analyze buffered CAN traffic and rank frames suited for replay testing"""

    __info__ = {
        "name": "CANBUS Replay Candidates",
        "description": (
            "Scores buffered CAN messages as replay candidates based on periodicity, "
            "payload uniqueness, and event-like behavior"
        ),
        "author": "KittySploit Team",
        "version": "1.0.0",
        "session_type": SessionType.CANBUS,
        "tags": ["canbus", "analyze", "replay", "automotive"],
        "references": [
            "https://attack.mitre.org/techniques/T0836/",
            "https://en.wikipedia.org/wiki/CAN_bus",
        ],
        "agent": {
            "risk": "passive",
            "effects": ["recon"],
            "expected_requests": 0,
            "reversible": True,
            "approval_required": False,
            "produces": ["risk_signals"],
            "cost": 0.5,
            "noise": 0.0,
            "value": 1.2,
            "requires": {
                "min_endpoints": 0,
                "min_params": 0,
                "tech_hints_any": [],
                "tech_hints_all": [],
                "specializations_any": [],
                "risk_signals_any": [],
                "auth_session": False,
                "capabilities_any": [],
                "capabilities_all": [],
                "confidence_min": {},
                "confidence_min_any": {},
                "endpoint_pattern_any": [],
                "param_any": [],
                "api_surface_ready": False,
            },
            "chain": {
                "produces_capabilities": [
                    {"capability": "canbus_replay_candidates", "from_detail": ""},
                ],
                "consumes_capabilities": [],
                "option_bindings": {},
                "suggested_followups": [
                    "post/canbus/exploits/inject_message",
                    "post/canbus/gather/dump_messages",
                ],
            },
        },
    }

    include_siblings = OptBool(
        False,
        "Also analyze sibling canbus sessions on the same bus",
        required=True,
    )
    min_score = OptFloat(0.35, "Minimum score (0-1) to report a candidate", required=True)
    top_n = OptInteger(20, "Maximum number of candidates to display", required=True)
    prefer_events = OptBool(
        True,
        "Boost event-like / low-frequency payloads over cyclic heartbeats",
        required=True,
    )
    output_file = OptString("", "Optional JSON output file", required=False)

    def check(self):
        """Check if session is a CANBUS session"""
        try:
            session_id_value = str(self.session_id)
            if not session_id_value:
                print_error("Session ID not set")
                return False

            if self.framework and hasattr(self.framework, "session_manager"):
                session = self.framework.session_manager.get_session(session_id_value)
                if session:
                    if session.session_type == "canbus":
                        return True
                    print_error(f"Session is not a CANBUS session (type: {session.session_type})")
                    return False
                print_error("Session not found")
                return False

            print_warning("Session manager not available - assuming valid session")
            return True
        except Exception as e:
            print_error(f"Error checking session: {e}")
            return False

    def run(self):
        """Rank replay candidates from buffered CAN traffic"""
        try:
            session_id_value = str(self.session_id)

            if not self.framework or not hasattr(self.framework, "session_manager"):
                print_error("Framework or session manager not available")
                return False

            session = self.framework.session_manager.get_session(session_id_value)
            if not session:
                print_error("Session not found")
                return False

            traffic = self._collect_traffic(session)
            if not traffic:
                print_warning("No buffered messages found to analyze")
                return False

            print_info("=" * 80)
            print_success("CANBUS Replay Candidate Analysis")
            print_info(f"Frames analyzed: {sum(len(v['messages']) for v in traffic.values())}")
            print_info(f"Distinct CAN IDs: {len(traffic)}")
            print_info("=" * 80)

            candidates = []
            for can_id, bucket in traffic.items():
                candidates.extend(self._score_id(can_id, bucket))

            candidates.sort(key=lambda c: c["score"], reverse=True)
            min_score = float(self.min_score)
            filtered = [c for c in candidates if c["score"] >= min_score]
            top_n = max(1, int(self.top_n))
            display = filtered[:top_n]

            results = {
                "analyzed_at": datetime.now().isoformat(),
                "session_id": session_id_value,
                "frames_analyzed": sum(len(v["messages"]) for v in traffic.values()),
                "can_ids_analyzed": len(traffic),
                "min_score": min_score,
                "candidate_count": len(filtered),
                "candidates": display,
            }

            self._display_results(display, results)

            if self.output_file:
                try:
                    with open(str(self.output_file), "w") as f:
                        json.dump(results, f, indent=2, default=str)
                    print_success(f"\nCandidates saved to: {self.output_file}")
                except Exception as e:
                    print_error(f"Error saving results: {e}")

            try:
                if session.data is not None:
                    session.data["replay_candidates"] = display
                    session.data["replay_candidates_at"] = results["analyzed_at"]
            except Exception:
                pass

            print_info("=" * 80)
            print_success(f"Replay analysis completed — {len(display)} candidate(s)")
            if display:
                print_info("Use post/canbus/exploits/inject_message with the suggested CAN ID and data")
            return True

        except Exception as e:
            print_error(f"Error analyzing replay candidates: {e}")
            import traceback
            traceback.print_exc()
            return False

    def _collect_traffic(self, session):
        """Build {can_id: {meta, messages}} from current (and optional sibling) sessions."""
        traffic = {}
        data = session.data or {}
        interface = data.get("interface")
        channel = data.get("channel")

        sessions = [session]
        if self.include_siblings and self.framework:
            for other in self.framework.session_manager.get_sessions():
                if other.id == session.id or other.session_type != "canbus":
                    continue
                odata = other.data or {}
                if odata.get("interface") == interface and odata.get("channel") == channel:
                    sessions.append(other)

        for sess in sessions:
            sdata = sess.data or {}
            can_id = sdata.get("can_id")
            if can_id is None:
                continue
            can_id = int(can_id)
            messages = sdata.get("messages", []) or []
            if not messages:
                continue

            if can_id not in traffic:
                traffic[can_id] = {
                    "can_id": can_id,
                    "can_id_hex": sdata.get("can_id_hex") or f"0x{can_id:03X}",
                    "is_extended": sdata.get("is_extended", False),
                    "messages": [],
                }
            traffic[can_id]["messages"].extend(messages)

        return traffic

    def _score_id(self, can_id, bucket):
        """Score individual payloads under a CAN ID for replay usefulness."""
        messages = bucket["messages"]
        can_id_hex = bucket["can_id_hex"]
        is_extended = bucket.get("is_extended", False)

        # Aggregate per payload
        by_payload = defaultdict(list)
        for msg in messages:
            payload = (msg.get("data") or "").upper().replace(" ", "")
            by_payload[payload].append(msg.get("timestamp", 0) or 0)

        timestamps = sorted(m.get("timestamp", 0) or 0 for m in messages)
        intervals = [timestamps[i + 1] - timestamps[i] for i in range(len(timestamps) - 1)]
        avg_interval = statistics.mean(intervals) if intervals else 0.0
        interval_cv = 0.0
        if intervals and avg_interval > 0:
            try:
                interval_cv = statistics.pstdev(intervals) / avg_interval
            except statistics.StatisticsError:
                interval_cv = 0.0

        total = len(messages)
        unique = len(by_payload)
        uniqueness_ratio = unique / total if total else 0.0

        # ID-level periodicity: low CV + high rate => cyclic (less interesting for replay)
        rate = 0.0
        if len(timestamps) >= 2 and timestamps[-1] > timestamps[0]:
            rate = total / (timestamps[-1] - timestamps[0])

        cyclic_score = 0.0
        if rate >= 5 and interval_cv < 0.35:
            cyclic_score = min(1.0, rate / 50.0)
        elif rate >= 1 and interval_cv < 0.5:
            cyclic_score = min(0.7, rate / 30.0)

        candidates = []
        for payload, ts_list in by_payload.items():
            if not payload:
                continue

            count = len(ts_list)
            frequency = count / total if total else 0.0
            length = len(payload) // 2

            # Rare payloads are better replay targets than constant heartbeats
            rarity = 1.0 - frequency
            # Single-shot or rare events score high
            event_boost = 0.0
            if count == 1:
                event_boost = 0.35
            elif frequency < 0.1:
                event_boost = 0.25
            elif frequency < 0.25:
                event_boost = 0.1

            # Penalize highly cyclic IDs unless this payload is rare within them
            cyclic_penalty = cyclic_score * (0.6 if self.prefer_events else 0.3) * frequency

            # Slight boost for typical command lengths (1-8 bytes) and non-zero data
            length_score = 0.1 if 1 <= length <= 8 else 0.0
            nonzero = any(payload[i:i + 2] != "00" for i in range(0, len(payload), 2))
            content_score = 0.1 if nonzero else 0.0

            # Diversity at ID level: more unique payloads => richer control surface
            diversity_score = min(0.2, uniqueness_ratio * 0.4)

            raw = rarity * 0.45 + event_boost + diversity_score + length_score + content_score - cyclic_penalty
            score = max(0.0, min(1.0, raw))

            if self.prefer_events and cyclic_score > 0.5 and frequency > 0.5:
                score *= 0.5

            reason = self._reason(count, frequency, cyclic_score, uniqueness_ratio, nonzero)

            candidates.append({
                "can_id": can_id,
                "can_id_hex": can_id_hex,
                "is_extended": is_extended,
                "data": payload,
                "data_length": length,
                "occurrences": count,
                "frequency": round(frequency, 4),
                "id_message_rate": round(rate, 4),
                "id_interval_cv": round(interval_cv, 4),
                "id_unique_payloads": unique,
                "behavior": "cyclic" if cyclic_score >= 0.5 else ("event" if frequency < 0.25 else "mixed"),
                "score": round(score, 4),
                "reason": reason,
                "suggested_inject": {
                    "can_id": can_id_hex,
                    "data": payload,
                    "extended_id": is_extended,
                    "count": 3,
                    "interval": 0.1,
                },
            })

        return candidates

    def _reason(self, count, frequency, cyclic_score, uniqueness_ratio, nonzero):
        parts = []
        if count == 1:
            parts.append("single occurrence")
        elif frequency < 0.1:
            parts.append("rare payload")
        if cyclic_score >= 0.5:
            parts.append("ID looks cyclic (heartbeat-like)")
        elif uniqueness_ratio > 0.5:
            parts.append("high payload diversity on ID")
        if not nonzero:
            parts.append("all-zero data")
        if frequency > 0.7:
            parts.append("dominant payload on ID")
        return "; ".join(parts) if parts else "moderate candidate"

    def _display_results(self, candidates, results):
        if not candidates:
            print_warning("No candidates met the minimum score threshold")
            print_info(f"  Try lowering MIN_SCORE (current: {results['min_score']})")
            return

        print_status("Top replay candidates")
        print_info("-" * 80)
        print_info(f"{'#':<3} {'Score':>5} {'Behavior':<8} {'ID':<10} {'Data':<20} {'Hits':>4}  Reason")
        print_info("-" * 80)

        for idx, c in enumerate(candidates, 1):
            data = c["data"]
            if len(data) > 18:
                data = data[:16] + ".."
            print_info(
                f"{idx:<3} {c['score']:>5.2f} {c['behavior']:<8} "
                f"{c['can_id_hex']:<10} {data:<20} {c['occurrences']:>4}  {c['reason']}"
            )

        print_info("-" * 80)
        best = candidates[0]
        inj = best["suggested_inject"]
        print_status("Suggested next step (highest score)")
        print_info(f"  use post/canbus/exploits/inject_message")
        print_info(f"  set CAN_ID {inj['can_id']}")
        print_info(f"  set DATA {inj['data']}")
        print_info(f"  set EXTENDED_ID {inj['extended_id']}")
        print_info(f"  set COUNT {inj['count']}")
        print_info(f"  set INTERVAL {inj['interval']}")
        print_warning("Replay may affect vehicle/device behavior — authorized testing only")
