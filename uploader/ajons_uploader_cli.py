#!/usr/bin/env python3
"""Ajons uploader pairing and direct local-to-Google upload commands."""
import argparse
import json
import os
import platform
import shutil
import subprocess
import sys
import time
import traceback
import urllib.request
from pathlib import Path

from security_redaction import redact_text

from tools import ajons_video_uploader as uploader
from tools import ajons_daemon as daemon
from tools.ajons_video_uploader import UploadError

VERSION = uploader.UPLOADER_VERSION


def _install_dir():
    if os.name == "nt":
        return Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData/Local")) / "Ajons"
    return Path.home() / ".local" / "bin"


def _installed_name():
    return "ajons-uploader.exe" if os.name == "nt" else "ajons-uploader"


def _debug_enabled():
    if os.environ.get("AJONS_DEBUG", "").strip().lower() in ("1", "true", "yes", "on"):
        return True
    return "--debug" in sys.argv


def _log_dir():
    if os.name == "nt":
        base = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData/Local"))
        return base / "Ajons" / "logs"
    if platform.system() == "Darwin":
        return Path.home() / "Library" / "Logs" / "Ajons"
    return Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local/share")) / "Ajons" / "logs"


def _log_path():
    return _log_dir() / "uploader.log"


def _write_traceback_to_log(exc):
    """Append the full (redacted) traceback for `exc` to the user log file."""
    try:
        log_dir = _log_dir()
        log_dir.mkdir(parents=True, exist_ok=True)
        tb = traceback.format_exc()
        entry = "\n===== %s =====\n%s\n" % (time.strftime("%Y-%m-%d %H:%M:%S"), redact_text(tb))
        with (_log_dir() / "uploader.log").open("a", encoding="utf-8") as stream:
            stream.write(entry)
    except Exception:
        pass


def _handle_error(exc, log_path, debug, command_name="unknown"):
    """Unified error handler for all uploader commands.

    Always writes the redacted full traceback to the log file.
    --debug / AJONS_DEBUG=1 also prints it to stderr.
    The short message always includes the log path.
    """
    _write_traceback_to_log(exc)
    msg = ("%s failed. Full details (tokens, device codes and secrets redacted) "
           "were written to: %s" % (command_name, str(log_path)))
    if debug:
        tb = traceback.format_exc()
        msg += "\n--- traceback ---\n" + redact_text(tb) + "\n--- end ---"
    return msg


def _update_user_path(directory):
    directory = str(directory)
    if os.name == "nt":
        try:
            import winreg
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, "Environment", 0,
                                 winreg.KEY_QUERY_VALUE | winreg.KEY_SET_VALUE)
            try:
                try:
                    current, kind = winreg.QueryValueEx(key, "Path")
                except FileNotFoundError:
                    current, kind = "", winreg.REG_EXPAND_SZ
                entries = [part.strip().rstrip("\\/").casefold() for part in current.split(";") if part.strip()]
                if directory.rstrip("\\/").casefold() not in entries:
                    new_path = current.rstrip(";") + (";" if current else "") + directory
                    winreg.SetValueEx(key, "Path", 0, kind, new_path)
            finally:
                winreg.CloseKey(key)
            return "User PATH updated. Open a new terminal to use ajons-uploader."
        except Exception:
            return "Add this folder to your user PATH: " + directory
    profile = Path.home() / (".zprofile" if os.environ.get("SHELL", "").endswith("zsh") else ".profile")
    line = 'export PATH="$HOME/.local/bin:$PATH"'
    try:
        if profile.exists() and profile.is_file() and os.access(profile, os.R_OK | os.W_OK):
            contents = profile.read_text(encoding="utf-8")
            if line not in contents:
                with profile.open("a", encoding="utf-8") as stream:
                    stream.write("\n# Ajons uploader PATH\n" + line + "\n")
            return "PATH updated in " + str(profile) + ". Open a new terminal."
    except OSError:
        pass
    return "Add this exact line to your shell profile: " + line


def _install():
    source = Path(sys.executable if getattr(sys, "frozen", False) else sys.argv[0]).resolve()
    destination_dir = _install_dir()
    destination_dir.mkdir(parents=True, exist_ok=True)
    destination = destination_dir / _installed_name()
    shutil.copy2(source, destination)
    if os.name != "nt":
        destination.chmod(destination.stat().st_mode | 0o111)
    print("Installed to: " + str(destination))
    print(_update_user_path(destination_dir))
    return 0


def _uninstall():
    destination = _install_dir() / _installed_name()
    try:
        destination.unlink()
        print("Removed: " + str(destination))
        return 0
    except FileNotFoundError:
        print("Ajons uploader is not installed at " + str(destination))
        return 0


def _version_tuple(value):
    try:
        return tuple(int(x) for x in value.split("."))
    except (AttributeError, ValueError):
        return ()


def _latest_version():
    url = "https://api.github.com/repos/Ajonswebtools/ajons-uploader-releases/releases/latest"
    request = urllib.request.Request(url, headers={"Accept": "application/vnd.github+json"})
    try:
        with urllib.request.urlopen(request, timeout=3) as response:
            return json.loads(response.read()).get("tag_name", "").lstrip("v") or None
    except Exception:
        return None


def _paired():
    try:
        kr = uploader._keyring()
        if kr and kr.get_password(uploader.STORE_SERVICE, "device-refresh"):
            return True
        path = uploader._config_file()
        if not path.is_file() or path.stat().st_mode & 0o077:
            return False
        return bool(json.loads(path.read_text(encoding="utf-8")).get("refresh_token"))
    except Exception:
        return False


def _stored_refresh_token():
    """Read the stored refresh token without calling any endpoint."""
    try:
        kr = uploader._keyring()
        if kr:
            token = kr.get_password(uploader.STORE_SERVICE, "device-refresh")
            if token:
                return token
        path = uploader._config_file()
        if path.is_file() and not (path.stat().st_mode & 0o077):
            data = json.loads(path.read_text(encoding="utf-8"))
            token = data.get("refresh_token")
            if token:
                return token
    except Exception:
        pass
    return None


def _save_refresh_token_to_store(token: str):
    """Persist a rotated refresh token back to the store."""
    try:
        kr = uploader._keyring()
        if kr:
            kr.set_password(uploader.STORE_SERVICE, "device-refresh", token)
            return True
        path = uploader._config_file()
        from tools.ajons_utils import _save_refresh_token as _persist
        _persist(token, ("file", path), allow_file=True)
        return True
    except Exception:
        return False


def _token_live_valid():
    """Check if the stored refresh token can still obtain an access token.

    Rotates the token on success and saves the replacement so the stored
    token never becomes stale. Returns (valid: bool, needs_repair: bool).
    On invalid_grant, needs_repair=True.
    """
    try:
        refresh_token = _stored_refresh_token()
        if not refresh_token:
            return False, False
        result = _json_request_with_retry("POST", "/device/token",
                                          {"refresh_token": refresh_token})
        if result.get("refresh_token") or result.get("access_token"):
            new_refresh = result.get("refresh_token") or refresh_token
            _save_refresh_token_to_store(new_refresh)
            return True, False
        return False, False
    except UploadError as exc:
        msg = str(exc).lower()
        if "invalid_grant" in msg:
            return False, True
        return False, False
    except Exception:
        return False, False


def _json_request_with_retry(method, path, payload):
    """Thin wrapper around uploader's JSON request that surfaces UploadError."""
    from tools.ajons_video_uploader import UploadError
    return uploader._json_request(method, path, payload)


def _serve(argv):
    parser = argparse.ArgumentParser(prog="ajons-uploader serve")
    parser.add_argument("--concurrency", type=int, default=daemon.DEFAULT_CONCURRENCY, help="Max concurrent uploads (default: 3)")
    parser.add_argument("--allow-insecure-file", action="store_true", help="Allow 0600 config file fallback on Linux")
    args = parser.parse_args(argv)

    # Check if already running
    if daemon._is_daemon_running():
        info = daemon._read_daemon_info()
        print(f"Daemon already running (PID {info.get('pid')}) on {info.get('socket')}")
        return 0

    import asyncio
    return asyncio.run(daemon.run_daemon(args.concurrency, args.allow_insecure_file))


def _status(argv):
    parser = argparse.ArgumentParser(prog="ajons-uploader status")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--session")
    args = parser.parse_args(argv[1:])

    latest = _latest_version()
    paired = _paired()
    daemon_running = daemon._is_daemon_running()

    # D7: When the daemon is running, use its cached token state to avoid
    # racing the daemon's own proactive token refresh. When the daemon is
    # off, never call the rotating /device/token endpoint: just report
    # whether a stored token exists ("unknown" validity) so status never
    # consumes the refresh token.
    if daemon_running:
        d_status = daemon.daemon_status()
        token_valid = d_status.get("token_valid", False)
        needs_repair = d_status.get("needs_repair", True)
        last_renewal_error = d_status.get("last_renewal_error")
    else:
        stored = _stored_refresh_token() is not None
        token_valid = "unknown" if stored else False
        needs_repair = not stored
        last_renewal_error = None

    base_result = {"installed_version": VERSION, "paired": paired,
                  "token_valid": token_valid,
                  "needs_repair": needs_repair,
                  "daemon_running": daemon_running,
                  "latest_version": latest,
                  "update_available": bool(latest and _version_tuple(latest) > _version_tuple(VERSION))}

    if needs_repair and not daemon_running:
        if args.json:
            print(json.dumps(base_result, separators=(",", ":")))
        else:
            print("Pairing expired. Run pair again.")
        return 1

    if args.session:
        session_result = uploader.local_status(args.session)
        base_result.update(session_result)

    if daemon_running:
        base_result["daemon"] = d_status
        if "token_valid" in d_status:
            base_result["token_valid"] = d_status["token_valid"]
        if "needs_repair" in d_status:
            base_result["needs_repair"] = d_status["needs_repair"]
        if "last_renewal_error" in d_status:
            base_result["last_renewal_error"] = d_status["last_renewal_error"]

    if args.json:
        print(json.dumps(base_result, separators=(",", ":")))
    else:
        daemon_info = ""
        if daemon._is_daemon_running():
            d = daemon.daemon_status()
            daemon_info = f"; daemon=running (jobs={d.get('running', 0)}/{d.get('concurrency', 3)}, token_valid={d.get('token_valid', False)})"
        print("ajons-uploader %s; paired=%s; token_valid=%s; needs_repair=%s; update_available=%s%s" %
              (VERSION, str(base_result["paired"]).lower(), str(base_result["token_valid"]).lower(),
               str(base_result["needs_repair"]).lower(), str(base_result["update_available"]).lower(), daemon_info))
    return 0


def _cancel(argv):
    parser = argparse.ArgumentParser(prog="ajons-uploader cancel")
    parser.add_argument("job_id", nargs="?")
    parser.add_argument("--session")
    args = parser.parse_args(argv[1:])

    if not daemon._is_daemon_running():
        print("Daemon not running")
        return 1

    if args.job_id:
        result = daemon.daemon_cancel(args.job_id)
    elif args.session:
        # Cancel all jobs for this session
        status = daemon.daemon_status()
        for job in status.get("jobs", []):
            if job["session_id"] == args.session and job["status"] in ("queued", "claiming", "uploading"):
                daemon.daemon_cancel(job["job_id"])
        result = {"cancelled": True}
    else:
        print("Specify --job-id or --session")
        return 1

    if "error" in result:
        print("Cancel failed: " + result["error"])
        return 1
    print("Cancelled")
    return 0


def _stop(argv):
    if not daemon._is_daemon_running():
        print("Daemon not running")
        return 0
    result = daemon.daemon_stop()
    print("Daemon stopping...")
    return 0


def _preflight(argv):
    parser = argparse.ArgumentParser(prog="ajons-uploader preflight")
    parser.add_argument("--server", help="MCP server base URL to fetch runbook version")
    args = parser.parse_args(argv[1:])

    log_path = _log_path()
    debug = _debug_enabled()
    results = []

    # 1. Version check
    try:
        latest = _latest_version()
        v_ok = bool(latest)
        results.append(("version", v_ok, "installed=%s latest=%s" % (VERSION, latest or "unknown")))
    except Exception as exc:
        results.append(("version", False, str(exc)))

    # 2. Token validity (use daemon cache when running to avoid racing daemon refresh.
    # When the daemon is off, never call the rotating /device/token endpoint: just
    # report whether a stored token exists ("unknown" validity) so preflight never
    # consumes the refresh token.)
    try:
        d_running = daemon._is_daemon_running()
        if d_running:
            d_status = daemon.daemon_status()
            token_valid = d_status.get("token_valid", False)
            needs_repair = d_status.get("needs_repair", True)
        else:
            stored = _stored_refresh_token() is not None
            token_valid = "unknown" if stored else False
            needs_repair = not stored
        token_ok = (token_valid is True or token_valid == "unknown") and not needs_repair
        results.append(("token", token_ok,
                        "valid=%s needs_repair=%s daemon=%s" %
                        (token_valid, needs_repair, d_running)))
    except Exception as exc:
        results.append(("token", "unknown", str(exc)))

    # 3. Keyring access
    try:
        kr = uploader._keyring()
        rt = kr.get_password(uploader.STORE_SERVICE, "device-refresh") if kr else None
        results.append(("keyring", bool(kr), "available=%s has_refresh_token=%s" % (bool(kr), bool(rt))))
    except Exception as exc:
        results.append(("keyring", False, str(exc)))

    # 4. Daemon state
    try:
        d_running = daemon._is_daemon_running()
        results.append(("daemon", True, "running=%s" % d_running))
    except Exception as exc:
        results.append(("daemon", False, str(exc)))

    # 5. Runbook version from server (skipped without --server, not a failure)
    runbook_version = None
    runbook_ok = True
    if args.server:
        try:
            import urllib.request
            url = args.server.rstrip("/") + "/mcp/call"
            req = urllib.request.Request(url, data=json.dumps({
                "jsonrpc": "2.0", "method": "get_upload_runbook", "params": {}
            }).encode(), headers={"Content-Type": "application/json"})
            with urllib.request.urlopen(req, timeout=5) as resp:
                data = json.loads(resp.read())
                runbook_version = data.get("result", {}).get("runbook_version")
            results.append(("runbook", True, "server_version=%s" % runbook_version))
        except Exception as exc:
            results.append(("runbook", False, "server unreachable: %s" % str(exc)[:100]))
    else:
        results.append(("runbook", True, "no --server given; skipping"))

    all_pass = all(r[1] for r in results)
    for name, ok, detail in results:
        print("%s: %s (%s)" % (name, "PASS" if ok else "FAIL", detail))
    print()
    print("preflight: %s" % ("ALL PASS" if all_pass else "FAILURES DETECTED"))
    return 0 if all_pass else 1


def _pair(argv):
    parser = argparse.ArgumentParser(prog="ajons-uploader pair")
    parser.add_argument("--device-name")
    parser.add_argument("--allow-insecure-file", action="store_true",
                        help="Explicitly allow a 0600 config-file fallback if the OS keyring is unavailable")
    args = parser.parse_args(argv[1:])
    log_path = _log_path()
    debug = _debug_enabled()
    try:
        uploader.pair(args.allow_insecure_file, args.device_name)
    except UploadError as exc:
        sys.stderr.write("Pairing failed: %s\n" % exc)
        return 1
    except Exception as exc:
        sys.stderr.write(_handle_error(exc, log_path, debug, "pair") + "\n")
        return 1
    return 0


def _upload(argv):
    parser = argparse.ArgumentParser(prog="ajons-uploader upload")
    parser.add_argument("--session", required=True)
    parser.add_argument("--file", required=True)
    parser.add_argument("--allow-insecure-file", action="store_true",
                        help="Use a previously opted-in 0600 config-file credential fallback")
    parser.add_argument("--detach", action="store_true", help="Deprecated: all uploads are now daemon-managed")
    parser.add_argument("--_worker", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args(argv)

    if args._worker:
        return uploader.upload_worker(args.session, args.file, args.allow_insecure_file) or 0

    log_path = _log_path()
    debug = _debug_enabled()
    try:
        uploader.upload(args.session, args.file, args.allow_insecure_file)
    except UploadError as exc:
        sys.stderr.write(str(exc) + "\n")
        return 1
    except KeyboardInterrupt:
        sys.stderr.write("Upload interrupted. Re-run with the same session to resume.\n")
        return 130
    except Exception as exc:
        sys.stderr.write(_handle_error(exc, log_path, debug, "upload") + "\n")
        return 1
    return 0


def _upload_media(argv):
    parser = argparse.ArgumentParser(prog="ajons-uploader upload-media")
    parser.add_argument("--session", required=True)
    parser.add_argument("--file", required=True)
    parser.add_argument("--allow-insecure-file", action="store_true",
                        help="Use a previously opted-in 0600 config-file credential fallback")
    args = parser.parse_args(argv)

    log_path = _log_path()
    debug = _debug_enabled()
    try:
        uploader.upload_media(args.session, args.file, args.allow_insecure_file)
    except UploadError as exc:
        sys.stderr.write(str(exc) + "\n")
        return 1
    except KeyboardInterrupt:
        sys.stderr.write("Upload interrupted.\n")
        return 130
    except Exception as exc:
        sys.stderr.write(_handle_error(exc, log_path, debug, "upload-media") + "\n")
        return 1
    return 0


def _upload_batch(argv):
    """upload-batch: process files one at a time with session-per-file verification."""
    parser = argparse.ArgumentParser(prog="ajons-uploader upload-batch")
    parser.add_argument("path", help="Folder containing video files, or comma-separated file list")
    parser.add_argument("--metadata", required=True, help="JSON file or JSON string with per-file metadata")
    parser.add_argument("--server", required=True, help="MCP server base URL")
    args = parser.parse_args(argv[1:])

    # Parse metadata
    try:
        if os.path.isfile(args.metadata):
            metadata = json.loads(Path(args.metadata).read_text(encoding="utf-8"))
        else:
            metadata = json.loads(args.metadata)
    except Exception as exc:
        sys.stderr.write("Invalid metadata: %s\n" % exc)
        return 1

    # Build file list
    files = []
    if os.path.isdir(args.path):
        for f in sorted(Path(args.path).iterdir()):
            if f.is_file() and f.stat().st_size > 0:
                files.append(str(f))
    else:
        files = [f.strip() for f in args.path.split(",") if f.strip()]

    if not files:
        print("No files to process.")
        return 0

    import urllib.request

    def mcp_call(method, params):
        url = args.server.rstrip("/") + "/mcp/call"
        req = urllib.request.Request(url, data=json.dumps({
            "jsonrpc": "2.0", "method": method, "params": params
        }).encode(), headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                return json.loads(resp.read())
        except Exception as exc:
            return {"error": str(exc)}

    report = []
    for file_path in files:
        path = Path(file_path)
        if not path.is_file():
            report.append((file_path, "SKIP", "file not found"))
            continue

        file_size = path.stat().st_size
        file_meta = metadata.get(path.name, metadata) if isinstance(metadata, dict) else metadata
        title = file_meta.get("title", path.stem) if isinstance(file_meta, dict) else str(file_meta)

        # Step 1: initiate session
        result = mcp_call("initiate_video_upload", {
            "channel_id": file_meta.get("channel_id", "") if isinstance(file_meta, dict) else "",
            "title": title,
            "total_bytes": file_size,
            "file_name": path.name,
            "privacy_status": file_meta.get("privacy_status", "private") if isinstance(file_meta, dict) else "private",
        })
        if "error" in result:
            report.append((file_path, "FAIL", "initiate: %s" % result["error"]))
            break
        session_id = result.get("result", {}).get("session_id")
        returned_bytes = result.get("result", {}).get("total_bytes")
        returned_title = result.get("result", {}).get("title")
        if not session_id:
            report.append((file_path, "FAIL", "no session_id returned"))
            break
        if returned_bytes != file_size:
            report.append((file_path, "FAIL",
                "Session size mismatch: local %s, server %s" % (file_size, returned_bytes)))
            break
        if returned_title != title:
            report.append((file_path, "FAIL",
                "Title mismatch: local '%s', server '%s'" % (title, returned_title)))
            break

        # Step 2: upload via CLI
        upload_result = _upload(["--session", session_id, "--file", str(path)])
        if upload_result != 0:
            report.append((file_path, "FAIL", "upload command returned %d" % upload_result))
            break

        # Step 3: verify
        result = mcp_call("verify_video", {"session_id": session_id})
        if "error" in result:
            report.append((file_path, "FAIL", "verify: %s" % result["error"]))
            break
        vr = result.get("result", {})
        if vr.get("success"):
            report.append((file_path, "PASS", "verified video_id=%s" % vr.get("video_id")))
        else:
            report.append((file_path, "FAIL", "verification not successful: %s" % vr))
            break

    print()
    print("=== Batch Report ===")
    for fname, status, detail in report:
        print("%s: %s - %s" % (fname, status, detail))
    failures = [r for r in report if r[1] == "FAIL"]
    if failures:
        print("Batch stopped at first failure. %d of %d files processed." % (len(report), len(files)))
        return 1
    print("All %d files uploaded and verified." % len(files))
    return 0


def _menu():
    while True:
        print("\nAjons Uploader\n1. Pair this computer\n2. Check status\n3. Install (so any agent can find it)\n4. Start daemon\n5. Stop daemon\n6. Exit")
        choice = input("Choose 1-6: ").strip()
        try:
            if choice == "1":
                _pair([])
            elif choice == "2":
                _status(["--json"])
            elif choice == "3":
                _install()
            elif choice == "4":
                print("Starting daemon in background...")
                if getattr(sys, "frozen", False):
                    cmd = [sys.executable, "serve", "--concurrency", str(daemon.DEFAULT_CONCURRENCY)]
                else:
                    cmd = [sys.executable, "-m", "tools.ajons_daemon", "serve", "--concurrency", str(daemon.DEFAULT_CONCURRENCY)]
                subprocess.Popen(cmd, start_new_session=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                time.sleep(1)
                print("Daemon started")
            elif choice == "5":
                _stop([])
            elif choice == "6":
                return 0
            else:
                print("Choose 1-6.")
        except UploadError as exc:
            print("Operation failed: " + str(exc))
        except Exception as exc:
            print("Error: " + str(exc))
        finally:
            input("Press Enter to return to the menu")


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    debug = _debug_enabled()
    argv = [a for a in argv if a != "--debug"]
    log_path = _log_path()
    try:
        if not argv and sys.stdin.isatty() and sys.stdout.isatty():
            return _menu()
        if argv == ["--version"]:
            print("ajons-uploader " + VERSION)
            return 0
        if argv == ["--help"]:
            print("Usage: ajons-uploader <command> [args...]")
            print()
            print("Commands:")
            print("  status      Show pairing and daemon status")
            print("  pair        Pair this computer with Ajons")
            print("  install     Install uploader to user PATH")
            print("  uninstall   Remove uploader from user PATH")
            print("  serve       Start upload daemon")
            print("  cancel      Cancel upload job(s)")
            print("  stop        Stop upload daemon")
            print("  upload      Upload a file")
            print("  upload-media  Upload a media file")
            print("  preflight   Run preflight checks (version, token, keyring, daemon, runbook)")
            print("  upload-batch  Upload multiple files one at a time with verification")
            print()
            print("Options:")
            print("  --version   Show version and exit")
            print("  --help      Show this help and exit")
            return 0
        if argv and argv[0] == "status":
            return _status(argv)
        if argv and argv[0] == "pair":
            return _pair(argv)
        if argv and argv[0] == "install":
            return _install()
        if argv and argv[0] == "uninstall":
            return _uninstall()
        if argv and argv[0] == "serve":
            return _serve(argv[1:])
        if argv and argv[0] == "cancel":
            return _cancel(argv[1:])
        if argv and argv[0] == "stop":
            return _stop(argv[1:])
        if argv and argv[0] == "preflight":
            return _preflight(argv[1:])
        if argv and argv[0] == "upload-batch":
            return _upload_batch(argv[1:])
        if argv and argv[0] in ("upload", "upload-media"):
            media_upload = argv[0] == "upload-media"
            if media_upload:
                return _upload_media(argv[1:])
            return _upload(argv[1:])
        print("Unknown command. Use: status, pair, install, uninstall, serve, cancel, stop, upload, upload-media")
        return 1
    except UploadError as exc:
        sys.stderr.write(str(exc) + "\n")
        return 1
    except KeyboardInterrupt:
        sys.stderr.write("Interrupted\n")
        return 130
    except Exception:
        sys.stderr.write(_handle_error(sys.exc_info()[1], log_path, debug, "ajons-uploader") + "\n")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())