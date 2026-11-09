"""Redaction helpers for credential- and session-bearing log messages."""
import logging
import re


_AUTH_RE = re.compile(r"(?i)(\bauthorization\s*[:=]\s*(?:bearer|token)\s+)[^\s,;\"']+")
_SECRET_FIELD_RE = re.compile(
    r"(?i)([\"']?(?:access_token|refresh_token|ticket_id|callback_secret|renewal_credential|"
    r"recovery_credential|session_url|upload_url)[\"']?\s*[:=]\s*)"
    r"(?:\"[^\"]*\"|'[^']*'|[^\s,;&}]+)"
)
_SESSION_URI_RE = re.compile(r"https?://[^\s\"'<>]*(?:upload_id=|uploadType=resumable)[^\s\"'<>]*", re.IGNORECASE)
_GOOGLE_UPLOAD_URI_RE = re.compile(
    r"https?://(?:www\.)?googleapis\.com/upload/youtube/v3/videos\?[^\s\"'<>]+",
    re.IGNORECASE,
)
_GOOGLE_ACCESS_TOKEN_RE = re.compile(r"\bya29\.[A-Za-z0-9._~-]+")


def redact_text(value: str) -> str:
    value = _AUTH_RE.sub(r"\1[REDACTED]", str(value))
    value = _SESSION_URI_RE.sub("[UPLOAD_SESSION_URI_REDACTED]", value)
    value = _SECRET_FIELD_RE.sub(r"\1[REDACTED]", value)
    value = _GOOGLE_UPLOAD_URI_RE.sub("[GOOGLE_UPLOAD_URI_REDACTED]", value)
    return _GOOGLE_ACCESS_TOKEN_RE.sub("[GOOGLE_ACCESS_TOKEN_REDACTED]", value)


class RedactingFilter(logging.Filter):
    """Sanitize formatted messages and exception tracebacks before handlers emit them."""

    def filter(self, record: logging.LogRecord) -> bool:
        record.msg = redact_text(record.getMessage())
        record.args = ()
        if record.exc_info:
            record.exc_text = redact_text(logging.Formatter().formatException(record.exc_info))
            record.exc_info = None
        elif record.exc_text:
            record.exc_text = redact_text(record.exc_text)
        return True
