from kittysploit import *
from lib.protocols.redis.redis_client import RedisClient

import re


class Module(Post, RedisClient):

    __info__ = {
        "name": "Redis Keyspace Profiler",
        "description": "Profile Redis keys, TTLs, memory usage, and suspicious naming patterns without dumping values by default",
        "author": "KittySploit Team",
        "session_type": SessionType.REDIS,
    'agent': {
        'risk': 'intrusive',
        'effects': ['active_exploitation'],
        'expected_requests': 2,
        'reversible': False,
        'approval_required': True,
        'produces': ['risk_signals'],
        'cost': 1.5,
        'noise': 0.5,
        'value': 1.0,
        'requires':         {'min_endpoints': 0,
         'min_params': 0,
         'tech_hints_any': [],
         'tech_hints_all': [],
         'specializations_any': [],
         'risk_signals_any': [],
         'auth_session': False,
         'capabilities_any': [],
         'capabilities_all': [],
         'confidence_min': {},
         'confidence_min_any': {},
         'endpoint_pattern_any': [],
         'param_any': [],
         'api_surface_ready': False},
        'chain':         {'produces_capabilities': [{'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 's7comm', 'from_detail': ''},
                                   {'capability': 'ot_assets', 'from_detail': ''},
                                   {'capability': 'ot_assets', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''}],
         'consumes_capabilities': [],
         'option_bindings': {},
         'suggested_followups': []},
    },
    }

    pattern = OptString("*", "SCAN match pattern", False)
    max_keys = OptInteger(200, "Maximum keys to inspect", False)
    sample_values = OptBool(False, "Sample short string values when they do not look secret", False)
    value_preview = OptInteger(120, "Maximum sampled value length", False)
    scan_count = OptInteger(100, "SCAN count hint", False)

    SECRET_HINTS = re.compile(
        r"(pass(word)?|passwd|secret|token|api[_-]?key|access[_-]?key|session|cookie|jwt|bearer|credential)",
        re.IGNORECASE,
    )

    def run(self):
        try:
            info = self.get_session_info()
            pattern = str(self.pattern or "*").strip() or "*"
            max_keys = max(1, int(self.max_keys))
            scan_count = max(10, int(self.scan_count))

            print_info("=" * 80)
            print_status("Redis keyspace profiler")
            print_info(f"Target: {info.get('host', 'localhost')}:{info.get('port', 6379)} db{info.get('db', 0)}")
            print_info(f"Pattern: {pattern} (max_keys={max_keys})")

            stats = {
                "total_seen": 0,
                "persistent": 0,
                "volatile": 0,
                "secret_named": 0,
                "memory_known": 0,
                "memory_bytes": 0,
            }
            by_type = {}
            interesting = []

            for raw_key in self.scan_keys(pattern=pattern, count=scan_count, max_keys=max_keys):
                key = self._text(raw_key)
                key_type = self._normal_type(self.get_key_type(raw_key))
                ttl = self.get_ttl(raw_key)
                memory = self._memory_usage(raw_key)
                preview = self._preview_value(raw_key, key, key_type)

                stats["total_seen"] += 1
                by_type[key_type] = by_type.get(key_type, 0) + 1
                if ttl < 0:
                    stats["persistent"] += 1
                else:
                    stats["volatile"] += 1
                if self.SECRET_HINTS.search(key):
                    stats["secret_named"] += 1
                if memory is not None:
                    stats["memory_known"] += 1
                    stats["memory_bytes"] += memory

                score = self._interest_score(key, key_type, ttl, memory)
                if score > 0:
                    interesting.append((score, key, key_type, ttl, memory, preview))

            print_info("-" * 80)
            print_status("Summary")
            print_info(f"Keys inspected: {stats['total_seen']}")
            print_info(f"Persistent keys: {stats['persistent']}")
            print_info(f"Keys with TTL: {stats['volatile']}")
            print_info(f"Secret-looking key names: {stats['secret_named']}")
            if stats["memory_known"]:
                print_info(f"Estimated sampled memory: {self._human_size(stats['memory_bytes'])}")

            print_info("-" * 80)
            print_status("Types")
            if by_type:
                for key_type, count in sorted(by_type.items(), key=lambda item: item[1], reverse=True):
                    print_info(f"  {key_type}: {count}")
            else:
                print_info("  (no keys matched)")

            print_info("-" * 80)
            print_status("Interesting keys")
            if not interesting:
                print_success("No suspicious key naming or TTL pattern detected in sample")
            else:
                interesting.sort(key=lambda item: item[0], reverse=True)
                for score, key, key_type, ttl, memory, preview in interesting[:50]:
                    ttl_text = "persistent" if ttl < 0 else f"ttl={ttl}s"
                    memory_text = self._human_size(memory) if memory is not None else "memory=?"
                    print_warning(f"[score={score}] {key} ({key_type}, {ttl_text}, {memory_text})")
                    if preview:
                        print_info(f"  preview: {preview}")

            print_info("=" * 80)
            print_success("Redis keyspace profiling completed")
            return True
        except ProcedureError:
            raise
        except Exception as exc:
            raise ProcedureError(FailureType.Unknown, f"Redis keyspace profiling failed: {exc}")

    def _normal_type(self, value) -> str:
        text = self._text(value).lower()
        if text.startswith("b'") and text.endswith("'"):
            text = text[2:-1]
        return text or "unknown"

    def _text(self, value) -> str:
        if isinstance(value, bytes):
            return value.decode("utf-8", errors="replace")
        return str(value)

    def _memory_usage(self, key):
        conn = self.get_redis_connection()
        try:
            value = conn.execute_command("MEMORY", "USAGE", key)
            return int(value) if value is not None else None
        except Exception:
            return None

    def _preview_value(self, key, key_name: str, key_type: str) -> str:
        if not bool(self.sample_values):
            return ""
        if key_type != "string":
            return ""
        if self.SECRET_HINTS.search(key_name):
            return "***masked: secret-looking key name***"
        try:
            value = self.get_redis_connection().get(key)
        except Exception:
            return ""
        if value is None:
            return ""
        value = self._text(value)
        max_length = max(20, int(self.value_preview))
        if len(value) > max_length:
            value = value[: max_length - 3] + "..."
        if self.SECRET_HINTS.search(value):
            return "***masked: secret-looking value***"
        return value.replace("\n", "\\n")

    def _interest_score(self, key: str, key_type: str, ttl: int, memory) -> int:
        score = 0
        if self.SECRET_HINTS.search(key):
            score += 5
        if ttl < 0 and key_type in ("string", "hash"):
            score += 1
        if key_type in ("stream", "zset"):
            score += 1
        if memory is not None and memory > 1024 * 1024:
            score += 2
        if key.startswith(("tmp:", "cache:")) and ttl < 0:
            score += 2
        return score

    def _human_size(self, value) -> str:
        if value is None:
            return "memory=?"
        size = float(value)
        for unit in ("B", "KB", "MB", "GB"):
            if size < 1024 or unit == "GB":
                return f"{size:.1f}{unit}" if unit != "B" else f"{int(size)}B"
            size /= 1024
        return f"{int(value)}B"
