#!/usr/bin/env python3
"""Ajons uploader pairing and direct local-to-Google upload commands."""
import argparse
import json
import os
import shutil
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

from tools import ajons_video_uploader as uploader
from tools import ajons_daemon as daemon
from uploader.ajons_video_uploader import UploadError

VERSION = uploader.UPLOADER_VERSION


def _install_dir():
    if os.name == "nt":
        return Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData/Local")) / "Ajons"
    return Path.home() / ".local" / "bin"


def _installed_name():
    return "ajons-uploader.exe" if os.name == "nt" else "ajons-uploader"


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
    base_result = {"installed_version": VERSION, "paired": _paired(),
                  "latest_version": latest,
                  "update_available": bool(latest and _version_tuple(latest) > _version_tuple(VERSION))}

    if args.session:
        session_result = uploader.local_status(args.session)
        base_result.update(session_result)

    if daemon._is_daemon_running():
        daemon_status = daemon.daemon_status()
        base_result["daemon"] = daemon_status

    if args.json:
        print(json.dumps(base_result, separators=(",", ":")))
    else:
        daemon_info = ""
        if daemon._is_daemon_running():
            d = daemon.daemon_status()
            daemon_info = f"; daemon=running (jobs={d.get('running', 0)}/{d.get('concurrency', 3)}, token_valid={d.get('token_valid', False)})"
        print("ajons-uploader %s; paired=%s; update_available=%s%s" %
              (VERSION, str(base_result["paired"]).lower(), str(base_result["update_available"]).lower(), daemon_info))
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


def _pair(argv):
    parser = argparse.ArgumentParser(prog="ajons-uploader pair")
    parser.add_argument("--device-name")
    parser.add_argument("--allow-insecure-file", action="store_true",
                        help="Explicitly allow a 0600 config-file fallback if the OS keyring is unavailable")
    args = parser.parse_args(argv[1:])
    try:
        uploader.pair(args.allow_insecure_file, args.device_name)
    except UploadError as exc:
        sys.stderr.write("Pairing failed: %s\n" % exc)
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

    try:
        uploader.upload(args.session, args.file, args.allow_insecure_file)
    except UploadError as exc:
        sys.stderr.write(str(exc) + "\n")
        return 1
    except KeyboardInterrupt:
        sys.stderr.write("Upload interrupted. Re-run with the same session to resume.\n")
        return 130
    except Exception:
        sys.stderr.write("Uploader failed unexpectedly. Sensitive details were suppressed.\n")
        return 1
    return 0


def _upload_media(argv):
    parser = argparse.ArgumentParser(prog="ajons-uploader upload-media")
    parser.add_argument("--session", required=True)
    parser.add_argument("--file", required=True)
    parser.add_argument("--allow-insecure-file", action="store_true",
                        help="Use a previously opted-in 0600 config-file credential fallback")
    args = parser.parse_args(argv)

    try:
        uploader.upload_media(args.session, args.file, args.allow_insecure_file)
    except UploadError as exc:
        sys.stderr.write(str(exc) + "\n")
        return 1
    except KeyboardInterrupt:
        sys.stderr.write("Upload interrupted.\n")
        return 130
    except Exception:
        sys.stderr.write("Uploader failed unexpectedly. Sensitive details were suppressed.\n")
        return 1
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
    try:
        if not argv and sys.stdin.isatty() and sys.stdout.isatty():
            return _menu()
        if argv == ["--version"]:
            print("ajons-uploader " + VERSION)
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
        sys.stderr.write("Uploader failed unexpectedly. Sensitive details were suppressed.\n")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())