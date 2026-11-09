#!/usr/bin/env python3
"""Ajons uploader pairing and direct local-to-Google upload commands."""
import argparse
import json
import urllib.request
import sys
import os
import shutil
import subprocess
import time
from pathlib import Path

from tools import ajons_video_uploader as uploader
from tools.ajons_video_uploader import UploadError, pair, upload, upload_media

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


def _menu():
    while True:
        print("\nAjons Uploader\n1. Pair this computer\n2. Check status\n3. Install (so any agent can find it)\n4. Exit")
        choice = input("Choose 1-4: ").strip()
        try:
            if choice == "1":
                pair(False, None)
            elif choice == "2":
                print("Paired" if _paired() else "Not paired. Choose 1 to pair this computer.")
            elif choice == "3":
                _install()
            elif choice == "4":
                return 0
            else:
                print("Choose 1, 2, 3 or 4.")
        except UploadError as exc:
            print("Pairing failed: " + str(exc))
        finally:
            input("Press Enter to return to the menu")


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


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    try:
        if not argv and sys.stdin.isatty() and sys.stdout.isatty():
            return _menu()
        if argv == ["--version"]:
            print("ajons-uploader " + VERSION)
            return 0
        if argv and argv[0] == "status":
            parser = argparse.ArgumentParser(prog="ajons-uploader status")
            parser.add_argument("--json", action="store_true")
            parser.add_argument("--session")
            args = parser.parse_args(argv[1:])
            latest = _latest_version()
            result = {"installed_version": VERSION, "paired": _paired(),
                      "latest_version": latest,
                      "update_available": bool(latest and _version_tuple(latest) > _version_tuple(VERSION))}
            if args.session:
                result.update(uploader.local_status(args.session))
            if args.json:
                print(json.dumps(result, separators=(",", ":")))
            else:
                print("ajons-uploader %s; paired=%s; update_available=%s" %
                      (VERSION, str(result["paired"]).lower(), str(result["update_available"]).lower()))
            return 0
        if argv and argv[0] == "pair":
            parser = argparse.ArgumentParser(prog="ajons-uploader pair")
            parser.add_argument("--device-name")
            parser.add_argument("--allow-insecure-file", action="store_true",
                                help="Explicitly allow a 0600 config-file fallback if the OS keyring is unavailable")
            args = parser.parse_args(argv[1:])
            try:
                pair(args.allow_insecure_file, args.device_name)
            except UploadError as exc:
                sys.stderr.write("Pairing failed: %s\n" % exc)
                return 1
            return 0
        if argv and argv[0] == "install":
            return _install()
        if argv and argv[0] == "uninstall":
            return _uninstall()
        media_upload = bool(argv and argv[0] == "upload-media")
        if argv and argv[0] in ("upload", "upload-media"):
            argv = argv[1:]
        parser = argparse.ArgumentParser(prog="ajons-uploader upload")
        parser.add_argument("--session", required=True)
        parser.add_argument("--file", required=True)
        parser.add_argument("--allow-insecure-file", action="store_true",
                            help="Use a previously opted-in 0600 config-file credential fallback")
        parser.add_argument("--detach", action="store_true", help="Run upload in the background and return immediately")
        parser.add_argument("--_worker", action="store_true", help=argparse.SUPPRESS)
        args = parser.parse_args(argv)
        if args._worker:
            return uploader.upload_worker(args.session, args.file, args.allow_insecure_file) or 0
        if args.detach and media_upload:
            raise UploadError("--detach is currently available for video uploads only.")
        if args.detach:
            return uploader.upload_detached(args.session, args.file, args.allow_insecure_file)
        (upload_media if media_upload else upload)(args.session, args.file, args.allow_insecure_file)
        return 0
    except UploadError as exc:
        sys.stderr.write(str(exc) + "\n")
        return 1
    except KeyboardInterrupt:
        sys.stderr.write("Upload interrupted. Re-run with the same session to resume.\n")
        return 130
    except Exception:
        # Never print tracebacks: HTTP/auth internals may contain sensitive values.
        sys.stderr.write("Uploader failed unexpectedly. Sensitive details were suppressed.\n")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())