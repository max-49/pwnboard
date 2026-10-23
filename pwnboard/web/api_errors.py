"""One JSON error format for the session API (every endpoint except the legacy ingest ones)."""
from flask import jsonify


def api_error(status, code, message, details=None):
    """A JSON error response: {"error": {"code": ..., "message": ..., "details": [...]}}.

    `code` is a short stable identifier clients can match on, `message` is for people, and
    `details` (optional) lists the individual problems when there are several.
    """
    error = {"code": code, "message": message}
    if details:
        error["details"] = details
    response = jsonify({"error": error})
    response.status_code = status
    return response
