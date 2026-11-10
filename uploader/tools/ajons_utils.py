"""Shared utilities for Ajons uploader (no circular imports)."""
import json
import os
import platform
import stat
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

try:
    import fcntl
except Exception:  # pragma: no cover - Unix without fcntl
    fcntl = None
try:
    import msvcrt
except Exception:  # pragma: no cover - non-Windows
    msvcrt = None

from security_redaction import redact_text

from tools.ajons_constants import (
    BASE_URL,
    CHUNK,
    STORE_SERVICE,
    UPLOADER_VERSION,
    UploadError,
)


def _pid_alive(pid):
    """Check if a process is alive. On Windows use OpenProcess; on POSIX use os.kill."""
    if pid <= 0:
        return False
    if os.name == "nt":
        try:
            import ctypes
            from ctypes import wintypes
            OpenProcess = ctypes.windll.kernel32.OpenProcess
            GetExitCodeProcess = ctypes.windll.kernel32.GetExitCodeProcess
            CloseHandle = ctypes.windll.kernel32.CloseHandle
            OpenProcess.restype = wintypes.HANDLE
            OpenProcess.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
            GetExitCodeProcess.restype = wintypes.BOOL
            GetExitCodeProcess.argtypes = (wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD))
            PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
            handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
            if not handle:
                return False
            exit_code = wintypes.DWORD()
            try:
                if GetExitCodeProcess(handle, ctypes.byref(exit_code)):
                    return exit_code.value == 259  # STILL_ACTIVE
                return False
            finally:
                CloseHandle(handle)
        except Exception:
            return False
    else:
        try:
            os.kill(pid, 0)
            return True
        except PermissionError:
            return True  # Process exists but we can't signal it
        except OSError:
            return False


def _keyring():
    try:
        import keyring
        backend = keyring.get_keyring()
        if getattr(backend, "priority", 0) <= 0:
            return None
        return keyring
    except Exception:
        return None


def _config_file():
    if os.name == "nt":
        base = Path(os.environ.get("APPDATA", Path.home() / "AppData/Roaming"))
        return base / "Ajons" / "uploader" / "device.json"
    if platform.system() == "Darwin":
        return Path.home() / "Library" / "Application Support" / "Ajons" / "uploader" / "device.json"
    return Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config")) / "ajons" / "uploader" / "device.json"


def _token_lock_path() -> Path:
    return _config_file().parent / "token.lock"


def _acquire_token_lock():
    """Acquire an exclusive cross-process file lock on the stored refresh token.

    Linux/macOS: fcntl.flock(LOCK_EX). Windows: msvcrt.locking(LK_LOCK).
    Works between parent and child PyInstaller processes. Returns a file
    descriptor to pass to _release_token_lock, or None if locking is unavailable.
    """
    lock_path = _token_lock_path()
    lock_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if os.name != "nt":
        try:
            os.chmod(lock_path.parent, 0o700)
        except OSError:
            pass
    fd = os.open(str(lock_path), os.O_CREAT | os.O_RDWR, 0o600)
    if os.name == "nt" and msvcrt is not None:
        try:
            msvcrt.locking(fd, msvcrt.LK_LOCK, 1)
        except OSError:
            os.close(fd)
            return None
    elif fcntl is not None and os.name != "nt":
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
        except OSError:
            os.close(fd)
            return None
    try:
        os.chmod(str(lock_path), 0o600)
    except OSError:
        pass
    return fd


def _release_token_lock(fd):
    if fd is None:
        return
    if os.name == "nt" and msvcrt is not None:
        try:
            msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
        except OSError:
            pass
    elif fcntl is not None and os.name != "nt":
        try:
            fcntl.flock(fd, fcntl.LOCK_UN)
        except OSError:
            pass
    try:
        os.close(fd)
    except OSError:
        pass


def _load_refresh_token(allow_file=False):
    kr = _keyring()
    if kr:
        token = kr.get_password(STORE_SERVICE, "device-refresh")
        if token:
            return token, ("keyring", kr)
    path = _config_file()
    if allow_file and platform.system() == "Linux" and path.exists():
        mode = stat.S_IMODE(path.stat().st_mode)
        if mode & 0o077:
            raise UploadError("Device credential file permissions are too broad; refusing to read it.")
        data = json.loads(path.read_text(encoding="utf-8"))
        return data["refresh_token"], ("file", path)
    if not allow_file and not kr:
        raise UploadError("No secure OS credential store is available. Pair again with --allow-insecure-file to opt in to a 0600 config file.")
    raise UploadError("No paired device found. Run ajons-uploader pair first.")


def _save_refresh_token(token, store, allow_file=False):
    kind, target = store
    if kind == "keyring":
        target.set_password(STORE_SERVICE, "device-refresh", token)
        return
    if (kind == "file" or allow_file) and platform.system() == "Linux" and allow_file:
        path = _config_file()
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        if os.name != "nt":
            os.chmod(path.parent, 0o700)
        temp = path.with_suffix(".tmp")
        temp.write_text(json.dumps({"refresh_token": token}), encoding="utf-8")
        if os.name != "nt":
            os.chmod(temp, 0o600)
        os.replace(temp, path)
        if os.name != "nt":
            os.chmod(path, 0o600)
        return
    raise UploadError("Secure credential store unavailable; refusing to save device credentials.")


def _request(method, url, payload=None, bearer=None, data=None, headers=None, timeout=60):
    body = json.dumps(payload).encode() if payload is not None else data
    h = dict(headers or {})
    h["X-Ajons-Uploader-Version"] = UPLOADER_VERSION
    if payload is not None:
        h["Content-Type"] = "application/json"
    if bearer:
        h["Authorization"] = "Bearer " + bearer
    req = urllib.request.Request(url, data=body, headers=h, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            return response.status, dict(response.headers), response.read()
    except urllib.error.HTTPError as exc:
        return exc.code, dict(exc.headers), exc.read()
    except Exception as exc:
        raise UploadError(_safe_text(str(exc))) from None


def _json_request(method, path, payload=None, bearer=None):
    status, _headers, body = _request(method, BASE_URL + path, payload=payload, bearer=bearer)
    try:
        result = json.loads(body) if body else {}
    except Exception:
        result = {}
    if status >= 400:
        # D2: Log every failed HTTP request: status, endpoint path (no query string),
        # and the redacted response body.
        _log_failed_http(method, path, status, result)
        raise UploadError("Ajons request failed (HTTP %d): %s" %
                          (status, _safe_text(result.get("error", "request rejected"))))
    return result


def _log_failed_http(method: str, path: str, status: int, body: dict):
    """Append a redacted failed-HTTP-request entry to the uploader log."""
    try:
        from pathlib import Path
        import time
        from security_redaction import redact_text
        # Extract endpoint path without query string
        endpoint = path.split("?")[0]
        log_dir = Path.home() / ".local" / "share" / "Ajons" / "logs"
        if __import__("os").name == "nt":
            log_dir = Path(__import__("os").environ.get("LOCALAPPDATA", Path.home() / "AppData/Local")) / "Ajons" / "logs"
        log_dir.mkdir(parents=True, exist_ok=True)
        entry = "\n===== %s =====\nHTTP %s %s -> %d\n%s\n" % (
            time.strftime("%Y-%m-%d %H:%M:%S"), method, endpoint, status,
            redact_text(json.dumps(body, separators=(",", ":"))[:2000]))
        with (log_dir / "uploader.log").open("a", encoding="utf-8") as f:
            f.write(entry)
    except Exception:
        pass


_http_request = _request


def _parse_range_header(value):
    try:
        _, part = value.split("=", 1)
        _start, end = part.split("-", 1)
        return int(end) + 1
    except (AttributeError, ValueError):
        return None


_SENSITIVE_VALUES = set()


def _remember_secret(value):
    if isinstance(value, str) and value:
        _SENSITIVE_VALUES.add(value)


def _safe_text(value):
    result = redact_text(str(value))
    for secret in sorted(_SENSITIVE_VALUES, key=len, reverse=True):
        result = result.replace(secret, "[REDACTED]")
    return result


def _copy_code(code):
    try:
        if os.name == "nt":
            import subprocess
            subprocess.run(["clip"], input=code, text=True, check=True,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        elif platform.system() == "Darwin" and shutil.which("pbcopy"):
            import subprocess
            subprocess.run(["pbcopy"], input=code, text=True, check=True,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        else:
            import shutil
            clipboard = shutil.which("wl-copy") or shutil.which("xclip")
            if clipboard:
                command = [clipboard, "-selection", "clipboard"] if clipboard.endswith("xclip") else [clipboard]
                import subprocess
                subprocess.run(command, input=code, text=True, check=True,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception:
        pass