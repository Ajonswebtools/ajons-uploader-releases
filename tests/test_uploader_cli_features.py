import json
import os
import sys
import time
from pathlib import Path

from uploader import ajons_uploader_cli as cli
from uploader import ajons_video_uploader as uploader
from uploader.ajons_video_uploader import UploadError


class _TTY:
    def isatty(self): return True
    def write(self, *a, **k): pass
    def flush(self, *a, **k): pass
    def readline(self): return "4\n"


def test_menu_shown_only_interactive_no_args(monkeypatch):
    called = []
    monkeypatch.setattr(cli, "_menu", lambda: called.append(True) or 0)
    monkeypatch.setattr(sys, "stdin", _TTY())
    monkeypatch.setattr(sys, "stdout", _TTY())
    assert cli.main([]) == 0
    assert called == [True]


def test_no_menu_when_args(monkeypatch, capsys):
    called = []
    monkeypatch.setattr(cli, "_menu", lambda: called.append(True) or 0)
    monkeypatch.setattr(cli, "_paired", lambda: False)
    monkeypatch.setattr(cli, "_latest_version", lambda: None)
    rc = cli.main(["status", "--json"])
    assert rc == 0
    assert called == []
    data = json.loads(capsys.readouterr().out)
    assert data["paired"] is False


def test_install_uses_temp_dir_and_reports_path(monkeypatch, tmp_path, capsys):
    dest = tmp_path / "install"
    if os.name == "nt":
        monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "lad"))
    else:
        monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setattr(cli, "_install_dir", lambda: dest)
    monkeypatch.setattr(cli.sys, "argv", [str(tmp_path / "ajons-uploader")])
    monkeypatch.setattr(cli.sys, "frozen", False, raising=False)
    (tmp_path / "ajons-uploader").write_text("bin")
    rc = cli.main(["install"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "Installed to:" in out
    assert (dest / ("ajons-uploader.exe" if os.name == "nt" else "ajons-uploader")).exists()


def test_uninstall_missing_is_idempotent(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(cli, "_install_dir", lambda: tmp_path / "missing")
    assert cli.main(["uninstall"]) == 0
    assert "not installed" in capsys.readouterr().out.lower()


def test_status_session_reads_local_status(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(uploader, "_config_file", lambda: tmp_path / "config.json")
    sp = uploader._status_path("sess1")
    sp.parent.mkdir(parents=True, exist_ok=True)
    sp.write_text(json.dumps({"session_id": "sess1", "status": "uploading", "pid": 99999999,
                              "total_bytes": 100, "bytes_uploaded": 50, "percent": 50,
                              "speed_bytes_per_second": 10, "eta_seconds": 5, "last_heartbeat": int(time.time())}))
    monkeypatch.setattr(cli, "_paired", lambda: True)
    monkeypatch.setattr(cli, "_latest_version", lambda: "1.0.6")
    assert cli.main(["status", "--json", "--session", "sess1"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["session_id"] == "sess1"
    assert data["percent"] == 50
    assert data["process_alive"] is False


def test_detach_writes_status_and_refuses_second_process(monkeypatch, tmp_path, capsys):
    video = tmp_path / "v.mp4"
    video.write_bytes(b"x" * 1024)
    monkeypatch.setattr(uploader, "_config_file", lambda: tmp_path / "config.json")
    calls = []

    class P:
        pid = 4242

    monkeypatch.setattr(uploader.subprocess, "Popen", lambda *a, **k: calls.append((a, k)) or P())
    assert uploader.upload_detached("sess2", str(video), False) == 0
    assert "Detached uploader started" in capsys.readouterr().out
    status = uploader.local_status("sess2")
    assert status["pid"] == 4242
    assert status["status"] == "starting"
    monkeypatch.setattr(uploader.os, "kill", lambda pid, sig: None)
    assert uploader.upload_detached("sess2", str(video), False) == 0
    assert "already running" in capsys.readouterr().out.lower()
    assert len(calls) == 1


def test_pair_respects_slow_down_and_interval(monkeypatch, capsys):
    responses = iter([
        {"device_code": "dc", "user_code": "ABCD-EFGH", "verification_uri": "https://example.test/device/verify",
         "expires_in": 600, "interval": 1},
        UploadError("slow_down"),
        {"refresh_token": "rt"},
    ])
    sleeps = []

    def fake_json(method, path, body=None, **k):
        r = next(responses)
        if isinstance(r, Exception):
            raise r
        return r

    monkeypatch.setattr(uploader, "_keyring", lambda: type("K", (), {"set_password": lambda *a: None})())
    monkeypatch.setattr(uploader, "_json_request", fake_json)
    monkeypatch.setattr(uploader.time, "sleep", lambda n: sleeps.append(n))
    monkeypatch.setattr(uploader.webbrowser, "open", lambda *a, **k: False)
    monkeypatch.setattr(uploader, "_copy_code", lambda *a, **k: None)
    uploader.pair()
    out = capsys.readouterr().out
    assert "Paired successfully" in out
    assert sleeps and sleeps[0] == 1
    assert sleeps[1] >= 6
