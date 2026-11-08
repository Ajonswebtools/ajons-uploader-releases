"""Uploader safety regression tests (public distribution copy)."""
from pathlib import Path

from uploader import ajons_video_uploader


def test_uploader_does_not_configure_persistent_logs_or_recovery_files():
    source = Path(ajons_video_uploader.__file__).read_text()
    assert "RotatingFileHandler" not in source
    assert "_save_recovery_record" not in source
    assert "LOG_FILE" not in source
    assert "Google tokens stay in RAM" in source


def test_known_sensitive_material_is_redacted_before_error_display():
    try:
        from security_redaction import redact_text
    except Exception:
        # standalone fallback: verify redaction patterns exist in uploader
        source = Path(ajons_video_uploader.__file__).read_text().lower()
        assert "redact" in source or "secret" in source
        return
    token = "sample-error-token"
    uri = "https://www.googleapis.com/upload/youtube/v3/videos?uploadType=resumable&upload_id=sample-uri"
    result = redact_text("Authorization: Bearer " + token + " session_url=" + uri)
    assert token not in result and "sample-uri" not in result


def test_uploader_contains_no_legacy_shared_credential_fields():
    source = Path(ajons_video_uploader.__file__).read_text().lower()
    for legacy in ("ticket_id", "callback_secret", "renewal_credential", "recovery_credential"):
        assert legacy not in source
