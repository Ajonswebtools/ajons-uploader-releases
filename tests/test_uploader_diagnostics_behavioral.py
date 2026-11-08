"""Uploader safety regression tests (public distribution copy)."""
from pathlib import Path


def test_no_persistent_token_logs_or_recovery_records():
    from uploader import ajons_video_uploader as uploader
    source = Path(uploader.__file__).read_text()
    assert "RotatingFileHandler" not in source
    assert "_save_recovery_record" not in source
    assert "LOG_FILE" not in source


def test_pairing_never_prints_device_or_refresh_tokens(monkeypatch, capsys):
    from uploader import ajons_video_uploader as uploader
    responses = iter([
        {"device_code": "synthetic-device-code", "user_code": "ABCD-EFGH",
         "verification_uri": "https://example.test/device/verify", "expires_in": 600, "interval": 1},
        {"refresh_token": "synthetic-refresh-token"},
    ])

    class Keyring:
        def set_password(self, *args): pass
        def get_password(self, *args): return None
        def delete_password(self, *args): pass

    monkeypatch.setattr(uploader, "_keyring", lambda: Keyring())
    monkeypatch.setattr(uploader, "_json_request", lambda *a, **k: next(responses))
    monkeypatch.setattr(uploader.time, "sleep", lambda _n: None)
    monkeypatch.setattr(uploader.webbrowser, "open", lambda *a, **k: False)
    monkeypatch.setattr(uploader, "_copy_code", lambda *a, **k: None)
    uploader.pair()
    output = capsys.readouterr()
    assert output.out.startswith("Code: ABCD-EFGH\nURL: https://example.test/device/verify\n")
    assert "Paired successfully" in output.out
    assert "synthetic-device-code" not in output.out + output.err
    assert "synthetic-refresh-token" not in output.out + output.err
