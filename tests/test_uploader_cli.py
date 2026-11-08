"""Tests for the paired-device uploader CLI."""
import json

from uploader import ajons_uploader_cli


def test_version(capsys):
    assert ajons_uploader_cli.main(["--version"]) == 0
    assert capsys.readouterr().out.strip() == "ajons-uploader 1.0.6"


def test_status_json_has_only_nonsecret_pairing_state(monkeypatch, capsys):
    monkeypatch.setattr(ajons_uploader_cli, "_latest_version", lambda: "1.0.6")
    monkeypatch.setattr(ajons_uploader_cli, "_paired", lambda: False)
    assert ajons_uploader_cli.main(["status", "--json"]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result == {"installed_version": "1.0.6", "paired": False,
                      "latest_version": "1.0.6", "update_available": False}


def test_pair_dispatch(monkeypatch):
    calls = []
    monkeypatch.setattr(ajons_uploader_cli, "pair", lambda allow, name: calls.append((allow, name)))
    assert ajons_uploader_cli.main(["pair", "--allow-insecure-file", "--device-name", "My PC"]) == 0
    assert calls == [(True, "My PC")]


def test_upload_dispatch(monkeypatch):
    calls = []
    monkeypatch.setattr(ajons_uploader_cli, "upload", lambda s, f, allow, media: calls.append((s, f, allow, media)))
    assert ajons_uploader_cli.main(["--session", "abc", "--file", "v.mp4"]) == 0
    assert calls == [("abc", "v.mp4", False, False)]
