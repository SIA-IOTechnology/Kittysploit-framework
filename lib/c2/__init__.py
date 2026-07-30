"""C2 channel helpers (beacon timing, profiles, polling agents, redirectors, ops log)."""

from lib.c2.beacon_profile import (
    BeaconProfile,
    is_past_kill_date,
    is_within_working_hours,
    next_sleep,
    parse_kill_date,
    parse_working_hours,
)
from lib.c2.beacon_timing import compute_poll_delay, jitter_seconds
from lib.c2.ops_log import C2OpsLog, get_ops_log
from lib.c2.redirector import RedirectorSpec, generate as generate_redirector
from lib.c2.chain import (
    CHAIN_TOKEN_HEADER,
    CHAIN_VIA_HEADER,
    generate_chain_token,
    parse_upstream_url,
    validate_chain_token,
)
from lib.c2.task_protocol import (
    AgentResult,
    AgentTask,
    make_download_task,
    make_ls_task,
    make_shell_task,
    make_upload_task,
    poll_payload_for_task,
)
from lib.c2.kitty_agent import build_kitty_agent_script

__all__ = [
    "AgentResult",
    "AgentTask",
    "BeaconProfile",
    "C2OpsLog",
    "CHAIN_TOKEN_HEADER",
    "CHAIN_VIA_HEADER",
    "RedirectorSpec",
    "build_kitty_agent_script",
    "compute_poll_delay",
    "generate_chain_token",
    "generate_redirector",
    "get_ops_log",
    "is_past_kill_date",
    "is_within_working_hours",
    "jitter_seconds",
    "make_download_task",
    "make_ls_task",
    "make_shell_task",
    "make_upload_task",
    "next_sleep",
    "parse_kill_date",
    "parse_upstream_url",
    "parse_working_hours",
    "poll_payload_for_task",
    "validate_chain_token",
]
