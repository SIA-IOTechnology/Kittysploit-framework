# Shared helpers for flow/response handling. Use this to avoid BadGzipFile when
# Content-Encoding says gzip but the body is not (e.g. raw HTML).


def safe_response_content(flow_response):
    """Return response body bytes. On ValueError (e.g. BadGzipFile), return raw_content."""
    if not flow_response:
        return b""
    try:
        return flow_response.content or b""
    except ValueError:
        return getattr(flow_response, "raw_content", None) or b""


def safe_response_size(flow_response):
    """Return response body length. Avoids flow.response.content when gzip decode fails."""
    if not flow_response:
        return None
    try:
        if hasattr(flow_response, "content") and flow_response.content:
            return len(flow_response.content)
    except ValueError:
        pass
    if hasattr(flow_response, "raw_content") and flow_response.raw_content is not None:
        return len(flow_response.raw_content)
    if hasattr(flow_response, "headers") and flow_response.headers:
        cl = flow_response.headers.get(b"Content-Length") or flow_response.headers.get("Content-Length")
        if cl:
            try:
                return int(cl.decode("utf-8") if isinstance(cl, bytes) else cl)
            except (ValueError, TypeError):
                pass
    return None
