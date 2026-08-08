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
from lib.c2.kitty_agent import build_kitty_agent_from_spec, build_kitty_agent_script
from lib.c2.agent_spec import AgentSpec
from lib.c2.backdoor_identity import apply_implant_identity
from lib.c2.stager_delivery import prepare_download_stager_if_needed

from lib.c2.download_stagers import (
    build_bitsadmin_download_exec,
    build_certutil_download_exec,
    build_curl_exe_download_exec,
    build_curl_pipe_bash,
    build_curl_pipe_python,
    build_msbuild_remote,
    build_mshta_remote,
    build_powershell_iex_download,
    build_python_urllib_pipe_python,
    build_regsvr32_sct,
    build_rundll32_mshtml,
    build_sct_iex_wrapper,
    build_stager_url,
    build_wget_pipe_python,
    build_wmic_xsl,
)
from lib.c2.database_bind import build_bind_session_hint
from lib.c2.bind_listener_launcher import launch_bind_listener
from lib.c2.kubernetes_bind import build_kubernetes_bind_hint
from lib.c2.mysql_bind import build_mysql_bind_hint, build_mysql_udf_exec_sql
from lib.c2.postgresql_notify_agent import build_postgresql_notify_agent_script
from lib.c2.slack_reverse_agent import build_slack_reverse_agent_script

__all__ = [
    "AgentSpec",
    "AgentResult",
    "AgentTask",
    "BeaconProfile",
    "C2OpsLog",
    "CHAIN_TOKEN_HEADER",
    "CHAIN_VIA_HEADER",
    "RedirectorSpec",
    "build_bitsadmin_download_exec",
    "build_bind_session_hint",
    "build_certutil_download_exec",
    "build_curl_exe_download_exec",
    "build_curl_pipe_bash",
    "build_curl_pipe_python",
    "apply_implant_identity",
    "build_kitty_agent_from_spec",
    "build_kitty_agent_script",
    "build_kubernetes_bind_hint",
    "build_msbuild_remote",
    "build_mshta_remote",
    "build_mysql_bind_hint",
    "build_mysql_udf_exec_sql",
    "prepare_download_stager_if_needed",
    "build_postgresql_notify_agent_script",
    "build_powershell_iex_download",
    "build_python_urllib_pipe_python",
    "build_regsvr32_sct",
    "build_rundll32_mshtml",
    "build_sct_iex_wrapper",
    "build_slack_reverse_agent_script",
    "build_stager_url",
    "build_wget_pipe_python",
    "build_wmic_xsl",
    "launch_bind_listener",
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
