"""Ajons direct uploader: device refresh credentials stay in the OS keyring; Google tokens stay in RAM."""
import getpass
import json
import os
import platform
import secrets
import stat
import sys
import threading
import time
import urllib.error
import urllib.request
import webbrowser
import subprocess
import shutil
from pathlib import Path

from security_redaction import redact_text


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


def _wait_for_worker_heartbeat(status_path, timeout=10):
    """Wait for the worker to write its first heartbeat to the status file."""
    start = time.monotonic()
    while time.monotonic() - start < timeout:
        try:
            data = json.loads(status_path.read_text(encoding="utf-8"))
            if data.get("status") in ("uploading", "retrying", "recovering") and data.get("last_heartbeat"):
                return True, data.get("pid")
        except Exception:
            pass
        time.sleep(0.5)
    return False, None


def _read_worker_stderr(log_path):
    """Read worker stderr log for error details."""
    try:
        if log_path.exists():
            return log_path.read_text(encoding="utf-8", errors="replace")[-4000:]
    except Exception:
        pass
    return ""

BASE_URL = "https://mcp.ajonswebtools.com"
CHUNK = 8 * 1024 * 1024
STORE_SERVICE = "com.ajonswebtools.ajons-uploader"
UPLOADER_VERSION = "1.0.7"
_MAX_RETRIES = 0  # No retry-count limit; time-based (6 hours continuous failure)
_BASE_BACKOFF = 5  # seconds
_MAX_BACKOFF = 300  # 5 minutes
_MAX_RESPAWNS = 5  # maximum worker respawns
_SENSITIVE_VALUES = set()
_ACTIVE_STATUS_PATH = None
_STATUS_STARTED = None
_STATUS_SAMPLE = None
_STATUS_LOCK = threading.Lock()


def _status_path(session_id):
    safe_id = "".join(ch for ch in str(session_id) if ch.isalnum() or ch in "-_" )[:100]
    return _config_file().parent / "status" / (safe_id + ".json")


def _log_path(session_id):
    safe_id = "".join(ch for ch in str(session_id) if ch.isalnum() or ch in "-_" )[:100]
    return _config_file().parent / "status" / (safe_id + ".log")


def _lock_path(session_id):
    safe_id = "".join(ch for ch in str(session_id) if ch.isalnum() or ch in "-_" )[:100]
    return _config_file().parent / "status" / (safe_id + ".lock")


def _write_status(**values):
    if not _ACTIVE_STATUS_PATH:
        return
    with _STATUS_LOCK:
        status = {}
        try:
            status = json.loads(_ACTIVE_STATUS_PATH.read_text(encoding="utf-8"))
        except Exception:
            pass
        status.update(values)
        status["last_heartbeat"] = int(time.time())
        temporary = _ACTIVE_STATUS_PATH.with_suffix(".%s.tmp" % threading.get_ident())
        temporary.parent.mkdir(parents=True, exist_ok=True)
        temporary.write_text(json.dumps(status, separators=(",", ":")), encoding="utf-8")
        if os.name != "nt":
            os.chmod(temporary, 0o600)
        os.replace(temporary, _ACTIVE_STATUS_PATH)


def _write_worker_log(session_id, message):
    """Append a line to the worker's stderr log file."""
    log_file = _log_path(session_id)
    try:
        log_file.parent.mkdir(parents=True, exist_ok=True)
        with log_file.open("a", encoding="utf-8") as f:
            f.write("[%s] %s\n" % (time.strftime("%Y-%m-%d %H:%M:%S"), message))
    except Exception:
        pass


def _acquire_lock(session_id):
    """Try to acquire a lock file for this session. Returns (locked, lock_file)."""
    lock_file = _lock_path(session_id)
    try:
        lock_file.parent.mkdir(parents=True, exist_ok=True)
        # Use O_EXCL for atomic lock creation
        fd = os.open(str(lock_file), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        os.write(fd, str(os.getpid()).encode())
        os.close(fd)
        return True, lock_file
    except FileExistsError:
        # Check if the PID is still alive AND heartbeat is recent
        try:
            pid = int(lock_file.read_text(encoding="utf-8").strip())
            if pid > 0:
                # Check if process is alive
                if _pid_alive(pid):
                    # Check heartbeat recency from status file
                    status_path = _status_path(session_id)
                    try:
                        data = json.loads(status_path.read_text(encoding="utf-8"))
                        hb = data.get("last_heartbeat")
                        if hb and (time.time() - int(hb)) < 60:
                            return False, lock_file  # Lock held by live process with recent heartbeat
                    except Exception:
                        pass
        except Exception:
            pass
        try:
            lock_file.unlink()
            fd = os.open(str(lock_file), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            os.write(fd, str(os.getpid()).encode())
            os.close(fd)
            return True, lock_file
        except Exception:
            return False, lock_file


def _release_lock(lock_file):
    try:
        if lock_file.exists():
            lock_file.unlink()
    except Exception:
        pass


def local_status(session_id):
    path = _status_path(session_id)
    try:
        result = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {"session_id": session_id, "status": "not_found", "process_alive": False,
                "percent": 0, "bytes_uploaded": 0, "speed_bytes_per_second": None,
                "eta_seconds": None, "last_heartbeat": None, "retry_count": 0,
                "last_error": None, "video_id": None,
                "next_action": "unknown session - verify session_id and try again"}
    pid = int(result.get("pid") or 0)
    alive = _pid_alive(pid)
    result["process_alive"] = alive
    # Auto-respawn dead worker (up to limit), but skip if status updated in last 60s
    if not alive and result.get("status") in ("starting", "uploading", "retrying", "recovering"):
        hb = result.get("last_heartbeat")
        if hb and (time.time() - int(hb)) < 60:
            # Heartbeat is recent, don't respawn yet
            pass
        else:
            _maybe_respawn_worker(session_id)
            # Re-read status after potential respawn
            try:
                result = json.loads(_status_path(session_id).read_text(encoding="utf-8"))
                alive = True
                pid = int(result.get("pid") or 0)
                if pid:
                    alive = _pid_alive(pid)
                result["process_alive"] = alive
            except Exception:
                pass
    # Determine next_action based on state
    result["next_action"] = _compute_next_action(result)
    return result


def _compute_next_action(status):
    """Compute the next action string for the agent based on status."""
    st = status.get("status")
    if st == "completed":
        vid = status.get("video_id")
        return "upload complete, video_id=%s" % vid if vid else "upload complete"
    if st == "failed":
        err = status.get("last_error") or "unknown error"
        return "failed permanently: %s, tell the user" % err
    if st in ("starting", "uploading", "retrying", "recovering"):
        hb_age = None
        hb = status.get("last_heartbeat")
        if hb:
            hb_age = int(time.time()) - int(hb)
        if not status.get("process_alive") and st != "completed":
            return "worker dead, run `ajons-uploader status --json --session <id>` to respawn"
        if hb_age is not None and hb_age > 300:
            return "heartbeat stale >5 min, verify local process and resume"
        return "wait and check again in ~5 min"
    return "unknown state"


def _keep_awake():
    if os.name == "nt":
        try:
            import ctypes
            ES_CONTINUOUS = 0x80000000
            ES_SYSTEM_REQUIRED = 0x00000001
            ES_AWAYMODE_REQUIRED = 0x00000040
            ctypes.windll.kernel32.SetThreadExecutionState(ES_CONTINUOUS | ES_SYSTEM_REQUIRED | ES_AWAYMODE_REQUIRED)
            return lambda: ctypes.windll.kernel32.SetThreadExecutionState(ES_CONTINUOUS)
        except Exception:
            return lambda: None
    if platform.system() == "Darwin" and shutil.which("caffeinate"):
        try:
            process = subprocess.Popen(["caffeinate", "-dimsu", "-w", str(os.getpid())],
                                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return lambda: process.terminate()
        except Exception:
            pass
    if platform.system() == "Linux" and shutil.which("systemd-inhibit"):
        try:
            process = subprocess.Popen(["systemd-inhibit", "--what=sleep", "--mode=block",
                                        "--why=Ajons video upload", "sleep", "infinity"],
                                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return lambda: process.terminate()
        except Exception:
            pass
    return lambda: None


def _remember_secret(value):
    if isinstance(value, str) and value:
        _SENSITIVE_VALUES.add(value)


def _safe_text(value):
    result = redact_text(str(value))
    for secret in sorted(_SENSITIVE_VALUES, key=len, reverse=True):
        result = result.replace(secret, "[REDACTED]")
    return result


class UploadError(Exception):
    pass


UploadNetworkError = UploadError


def _parse_range_header(value):
    try:
        _, part = value.split("=", 1)
        _start, end = part.split("-", 1)
        return int(end) + 1
    except (AttributeError, ValueError):
        return None


def _chunk_size(total_bytes, remaining):
    if remaining <= 0:
        return 0
    if remaining == total_bytes and remaining <= CHUNK:
        return remaining
    size = min(CHUNK, remaining)
    rounded = size - (size % (256 * 1024))
    return rounded or min(remaining, 256 * 1024)


def _is_retryable_error(status_code, exception=None):
    """Determine if an error is retryable (5xx, timeout, connection reset)."""
    if status_code in (500, 502, 503, 504):
        return True
    if exception:
        err_str = str(exception).lower()
        if any(x in err_str for x in ("timeout", "connection reset", "connection refused", "temporary failure", "network unreachable")):
            return True
    return False


def _is_permanent_error(status_code, error_body=""):
    """Determine if an error is permanent (session expired, channel not authorized, file issues)."""
    if status_code in (400, 404, 410):
        return True
    if status_code in (401, 403):
        # Could be token expiry (retryable) or scope issue (permanent)
        # We'll treat as retryable first, then permanent if renew fails
        return "insufficient_permissions" in error_body or "quota" in error_body.lower()
    return False


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


_http_request = _request


def _json_request(method, path, payload=None, bearer=None):
    status, _headers, body = _request(method, BASE_URL + path, payload=payload, bearer=bearer)
    try:
        result = json.loads(body) if body else {}
    except Exception:
        result = {}
    if status >= 400:
        raise UploadError("Ajons request failed (HTTP %d): %s" %
                          (status, _safe_text(result.get("error", "request rejected"))))
    return result


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


def pair(allow_insecure_file=False, device_name=None):
    store = _keyring()
    if not store and not allow_insecure_file:
        raise UploadError("No secure OS credential store is available. Use --allow-insecure-file only if you accept a 0600 config file.")
    device_name = device_name or platform.node() or "Ajons uploader"
    response = _json_request("POST", "/device/code", {
        "device_name": device_name,
        "os": platform.platform()[:80],
    })
    user_code = response["user_code"]
    verification_url = response.get("verification_uri_complete") or response["verification_uri"]
    print("Code: " + user_code, flush=True)
    print("URL: " + verification_url, flush=True)
    if sys.stdin.isatty() and sys.stdout.isatty():
        try:
            webbrowser.open(verification_url)
        except Exception:
            pass
        _copy_code(user_code)
    device_code = response["device_code"]
    _remember_secret(device_code)
    interval = int(response.get("interval", 5))
    deadline = time.monotonic() + int(response.get("expires_in", 600))
    while time.monotonic() < deadline:
        time.sleep(interval)
        try:
            result = _json_request("POST", "/device/token", {"device_code": device_code})
        except UploadError as exc:
            message = str(exc)
            if "authorization_pending" in message:
                continue
            if "slow_down" in message:
                interval += 5
                continue
            raise
        refresh_token = result.get("refresh_token")
        if not refresh_token:
            raise UploadError("Pairing response did not include a device credential.")
        _remember_secret(refresh_token)
        if store:
            store.set_password(STORE_SERVICE, "device-refresh", refresh_token)
        else:
            _save_refresh_token(refresh_token, ("file", _config_file()), allow_file=True)
        print("Paired successfully", flush=True)
        return
    raise UploadError("Device pairing expired. Run pair again.")


def _copy_code(code):
    try:
        if os.name == "nt":
            subprocess.run(["clip"], input=code, text=True, check=True,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        elif platform.system() == "Darwin" and shutil.which("pbcopy"):
            subprocess.run(["pbcopy"], input=code, text=True, check=True,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        else:
            clipboard = shutil.which("wl-copy") or shutil.which("xclip")
            if clipboard:
                command = [clipboard, "-selection", "clipboard"] if clipboard.endswith("xclip") else [clipboard]
                subprocess.run(command, input=code, text=True, check=True,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception:
        pass


def _renew_device_access(state):
    _remember_secret(state.get("refresh_token"))
    result = _json_request("POST", "/device/token", {"refresh_token": state["refresh_token"]})
    state["refresh_token"] = result["refresh_token"]
    _remember_secret(state["refresh_token"])
    _save_refresh_token(state["refresh_token"], state["store"], state["allow_file"])
    state["device_access"] = result["access_token"]
    _remember_secret(state["device_access"])
    state["device_expiry"] = time.monotonic() + int(result.get("expires_in", 600))


def _device_access(state):
    if time.monotonic() >= state.get("device_expiry", 0) - 30:
        _renew_device_access(state)
    return state["device_access"]


def _request_json_with_device(method, path, payload, state):
    return _json_request(method, path, payload, _device_access(state))


def _start_heartbeat(session_id, state):
    stop = threading.Event()

    def run():
        while not stop.wait(15):
            try:
                _request_json_with_device(
                    "POST", "/uploads/%s/heartbeat" % session_id, {}, state)
                _write_status(status="uploading", heartbeat_interval_seconds=15)
            except Exception:
                pass

    thread = threading.Thread(target=run, name="ajons-upload-heartbeat", daemon=True)
    thread.start()
    return stop, thread


def _probe(uri, token, size):
    try:
        status, headers, _body = _http_request("PUT", uri, bearer=token, data=b"", headers={
            "Content-Length": "0", "Content-Range": "bytes */%d" % size,
            "Content-Type": "application/octet-stream",
        })
    except Exception:
        return None
    if status == 308:
        return {"offset": _parse_range_header(headers.get("Range")) or 0, "video_id": None}
    if status in (200, 201):
        try:
            video_id = json.loads(_body).get("id")
        except Exception:
            video_id = None
        return {"offset": size, "video_id": video_id}
    if status in (404, 410):
        raise UploadError("Google upload session expired.")
    return None


def _probe_session_position(session_uri, access_token, total_bytes=None, timeout=60):
    """Backward compatibility wrapper for tests."""
    return _probe(session_uri, access_token, total_bytes or 0)


def _probe_with_retry(session_id, uri, access_token, size, state, retry_count=0):
    """Probe Google for confirmed offset with retry logic."""
    while True:
        try:
            return _probe(uri, access_token, size)
        except UploadError as exc:
            if "expired" in str(exc).lower():
                raise
            if retry_count >= 3:
                raise
            retry_count += 1
            wait = min(_BASE_BACKOFF * (2 ** (retry_count - 1)), _MAX_BACKOFF)
            _write_worker_log(session_id, "Probe failed (attempt %d): %s, waiting %ds" % (retry_count, _safe_text(str(exc)), wait))
            time.sleep(wait)


def _upload_chunk_with_retry(uri, access_token, chunk, offset, end, size, session_id, state):
    """Upload a chunk with time-based retry logic for 5xx/timeouts (6 hours continuous failure)."""
    headers = {
        "Content-Length": str(len(chunk)),
        "Content-Range": "bytes %d-%d/%d" % (offset, end, size),
        "Content-Type": "video/mp4",
    }
    retry_start = time.time()
    retry_count = 0
    while True:
        try:
            return _request(
                "PUT", uri, bearer=access_token, data=chunk, headers=headers, timeout=180)
        except UploadError as exc:
            # Network-level exception (timeout, connection reset)
            retry_count += 1
            wait = min(_BASE_BACKOFF * (2 ** (retry_count - 1)), _MAX_BACKOFF)
            _write_status(last_error="Network error: %s (retry %d, waiting %ds, %.0f min continuous)" %
                          (_safe_text(str(exc)), retry_count, wait, (time.time() - retry_start) / 60),
                          retry_count=retry_count, status="retrying", retry_start_time=retry_start)
            _write_worker_log(session_id, "Network error at offset %d (attempt %d): %s, waiting %ds" %
                              (offset, retry_count, _safe_text(str(exc)), wait))
            # Probe for confirmed offset before retrying
            position = _probe_with_retry(session_id, uri, access_token, size, state)
            if position and position.get("video_id"):
                return 200, {}, json.dumps({"id": position["video_id"]}).encode()
            if position:
                offset = position["offset"]
            # Check 6-hour minimum before giving up
            if time.time() - retry_start >= 21600:  # 6 hours
                raise UploadError("Upload failed after 6 hours of continuous network errors at offset %d" % offset)
            time.sleep(wait)
            continue
        except Exception as exc:
            # This catches urllib errors (timeout, connection reset)
            retry_count += 1
            wait = min(_BASE_BACKOFF * (2 ** (retry_count - 1)), _MAX_BACKOFF)
            _write_status(last_error="Connection error: %s (retry %d, waiting %ds, %.0f min continuous)" %
                          (_safe_text(str(exc)), retry_count, wait, (time.time() - retry_start) / 60),
                          retry_count=retry_count, status="retrying", retry_start_time=retry_start)
            _write_worker_log(session_id, "Connection error at offset %d (attempt %d): %s, waiting %ds" %
                              (offset, retry_count, _safe_text(str(exc)), wait))
            position = _probe_with_retry(session_id, uri, access_token, size, state)
            if position and position.get("video_id"):
                return 200, {}, json.dumps({"id": position["video_id"]}).encode()
            if position:
                offset = position["offset"]
            if time.time() - retry_start >= 21600:
                raise UploadError("Upload failed after 6 hours of continuous connection errors at offset %d" % offset)
            time.sleep(wait)
            continue


def upload(session_id, file_path, allow_insecure_file=False):
    path = Path(file_path)
    if not path.is_file() or path.stat().st_size <= 0:
        raise UploadError("Video file does not exist or is empty.")
    size = path.stat().st_size
    mtime_ns = path.stat().st_mtime_ns
    abs_path = str(path.resolve())
    _write_status(status="starting", total_bytes=size, file_name=path.name,
                  file_path=abs_path, file_size=size, file_mtime_ns=mtime_ns,
                  bytes_uploaded=0, percent=0, speed_bytes_per_second=0, eta_seconds=None,
                  retry_count=0, last_error=None, retry_start_time=None)
    refresh_token, credential_store = _load_refresh_token(allow_insecure_file)
    state = {"refresh_token": refresh_token, "store": credential_store,
             "allow_file": allow_insecure_file, "device_expiry": 0}
    _renew_device_access(state)
    claim = _request_json_with_device("POST", "/uploads/%s/claim" % session_id, {}, state)
    uri, access_token = claim["upload_uri"], claim["access_token"]
    _remember_secret(uri)
    _remember_secret(access_token)
    google_expiry = time.monotonic() + int(claim.get("expires_in", 3600))
    position = _probe(uri, access_token, size) or {"offset": 0, "video_id": None}
    offset = position["offset"]
    _write_status(status="uploading", total_bytes=size, bytes_uploaded=offset,
                  percent=round((offset / size) * 100, 2), pid=os.getpid(),
                  retry_count=0, last_error=None)

    def finish(video_id):
        if not video_id:
            raise UploadError("YouTube reports the session complete but returned no video id.")
        result = _request_json_with_device("POST", "/uploads/%s/complete" % session_id,
                                           {"video_id": video_id}, state)
        if not result.get("verified"):
            raise UploadError("Upload reached YouTube; server verification is pending. Re-run with the same session to check.")
        print(json.dumps({"type": "complete", "bytes_uploaded": size, "total_bytes": size},
                         separators=(",", ":")), flush=True)
        _write_status(status="completed", bytes_uploaded=size, percent=100,
                      speed_bytes_per_second=0, eta_seconds=0, video_id=video_id,
                      retry_count=0, last_error=None)

    if position["video_id"]:
        finish(position["video_id"])
        return

    with path.open("rb") as file:
        while offset < size:
            if time.monotonic() >= google_expiry - 60:
                renewed = _request_json_with_device("POST", "/uploads/%s/renew" % session_id, {}, state)
                access_token = renewed["access_token"]
                _remember_secret(access_token)
                google_expiry = time.monotonic() + int(renewed.get("expires_in", 3600))
            file.seek(offset)
            chunk = file.read(min(CHUNK, size - offset))
            end = offset + len(chunk) - 1
            heartbeat_stop, heartbeat_thread = _start_heartbeat(session_id, state)
            try:
                status, headers, body = _request(
                    "PUT", uri, bearer=access_token, data=chunk, headers={
                        "Content-Length": str(len(chunk)),
                        "Content-Range": "bytes %d-%d/%d" % (offset, end, size),
                        "Content-Type": "video/mp4",
                    }, timeout=180)
            except UploadError as exc:
                # Network-level error - use time-based retry (6 hours continuous failure)
                retry_start = time.time()
                retry_count = 0
                while True:
                    retry_count += 1
                    wait = min(_BASE_BACKOFF * (2 ** (retry_count - 1)), _MAX_BACKOFF)
                    _write_status(last_error="Network error: %s (retry %d, waiting %ds, %.0f min continuous)" %
                                  (_safe_text(str(exc)), retry_count, wait, (time.time() - retry_start) / 60),
                                  retry_count=retry_count, status="retrying", retry_start_time=retry_start)
                    _write_worker_log(session_id, "Network error at offset %d (retry %d): %s, waiting %ds" %
                                      (offset, retry_count, _safe_text(str(exc)), wait))
                    # Probe for confirmed offset
                    position = _probe_with_retry(session_id, uri, access_token, size, state)
                    if position and position.get("video_id"):
                        finish(position["video_id"])
                        return
                    if position:
                        offset = position["offset"]
                    if time.time() - retry_start >= 21600:
                        raise UploadError("Upload failed after 6 hours of continuous network errors at offset %d" % offset)
                    # Renew tokens if needed
                    if time.monotonic() >= google_expiry - 60:
                        renewed = _request_json_with_device("POST", "/uploads/%s/renew" % session_id, {}, state)
                        access_token = renewed["access_token"]
                        _remember_secret(access_token)
                        google_expiry = time.monotonic() + int(renewed.get("expires_in", 3600))
                    time.sleep(wait)
                    # Retry the chunk
                    file.seek(offset)
                    chunk = file.read(min(CHUNK, size - offset))
                    end = offset + len(chunk) - 1
                    try:
                        status, headers, body = _request(
                            "PUT", uri, bearer=access_token, data=chunk, headers={
                                "Content-Length": str(len(chunk)),
                                "Content-Range": "bytes %d-%d/%d" % (offset, end, size),
                                "Content-Type": "video/mp4",
                            }, timeout=180)
                    except UploadError:
                        continue
                    # If we get here, we have an HTTP response - break to let outer loop handle it
                    break
            finally:
                heartbeat_stop.set()
                heartbeat_thread.join(timeout=2)
            
            if status in (200, 201):
                try:
                    video_id = json.loads(body).get("id")
                except Exception:
                    video_id = None
                if not video_id:
                    raise UploadError("Google completed the upload without returning a video id.")
                finish(video_id)
                return
            if status == 308:
                value = headers.get("Range", "")
                try:
                    offset = int(value.rsplit("-", 1)[1]) + 1 if value else 0
                except (ValueError, IndexError):
                    position = _probe(uri, access_token, size) or {"offset": 0, "video_id": None}
                    if position["video_id"]:
                        finish(position["video_id"])
                        return
                    offset = position["offset"]
                _request_json_with_device("POST", "/uploads/%s/progress" % session_id,
                                          {"bytes_uploaded": offset}, state)
                print(json.dumps({"type": "progress", "bytes_uploaded": offset, "total_bytes": size},
                                 separators=(",", ":")), flush=True)
                global _STATUS_SAMPLE
                now = time.monotonic()
                speed = 0
                if _STATUS_SAMPLE:
                    previous_bytes, previous_time = _STATUS_SAMPLE
                    elapsed = max(now - previous_time, 0.001)
                    speed = max(0, int((offset - previous_bytes) / elapsed))
                _STATUS_SAMPLE = (offset, now)
                remaining = max(0, size - offset)
                _write_status(status="uploading", bytes_uploaded=offset,
                              percent=round((offset / size) * 100, 2),
                              speed_bytes_per_second=speed,
                              eta_seconds=(int(remaining / speed) if speed else None),
                              retry_count=0, last_error=None, retry_start_time=None, respawn_count=0)
                continue
            if status in (401, 403):
                renewed = _request_json_with_device("POST", "/uploads/%s/renew" % session_id, {}, state)
                access_token = renewed["access_token"]
                _remember_secret(access_token)
                google_expiry = time.monotonic() + int(renewed.get("expires_in", 3600))
                continue
            if _is_retryable_error(status):
                # Retryable HTTP error (5xx) - use time-based retry (6 hours continuous failure)
                retry_start = time.time()
                _write_status(last_error="Google HTTP %d: %s (will retry)" %
                              (status, _safe_text(body.decode("utf-8", "replace")[:200])),
                              retry_count=1, status="retrying", retry_start_time=retry_start)
                retry_count = 0
                while True:
                    retry_count += 1
                    wait = min(_BASE_BACKOFF * (2 ** (retry_count - 1)), _MAX_BACKOFF)
                    _write_status(last_error="Google HTTP %d (retry %d, waiting %ds, %.0f min continuous)" %
                                  (status, retry_count, wait, (time.time() - retry_start) / 60),
                                  retry_count=retry_count, status="retrying", retry_start_time=retry_start)
                    _write_worker_log(session_id, "Google HTTP %d at offset %d (retry %d): %s, waiting %ds" %
                                      (status, offset, retry_count, _safe_text(body.decode("utf-8", "replace")[:200]), wait))
                    # Probe for confirmed offset
                    position = _probe_with_retry(session_id, uri, access_token, size, state)
                    if position and position.get("video_id"):
                        finish(position["video_id"])
                        return
                    if position:
                        offset = position["offset"]
                    # Renew tokens if needed
                    if time.monotonic() >= google_expiry - 60:
                        renewed = _request_json_with_device("POST", "/uploads/%s/renew" % session_id, {}, state)
                        access_token = renewed["access_token"]
                        _remember_secret(access_token)
                        google_expiry = time.monotonic() + int(renewed.get("expires_in", 3600))
                    time.sleep(wait)
                    # Retry the chunk
                    file.seek(offset)
                    chunk = file.read(min(CHUNK, size - offset))
                    end = offset + len(chunk) - 1
                    try:
                        status, headers, body = _request(
                            "PUT", uri, bearer=access_token, data=chunk, headers={
                                "Content-Length": str(len(chunk)),
                                "Content-Range": "bytes %d-%d/%d" % (offset, end, size),
                                "Content-Type": "video/mp4",
                            }, timeout=180)
                    except UploadError:
                        continue
                    if status in (200, 201):
                        try:
                            video_id = json.loads(body).get("id")
                        except Exception:
                            video_id = None
                        if video_id:
                            finish(video_id)
                            return
                    if status == 308:
                        # Success - reset retry timer on successful chunk
                        break
                    if status in (401, 403):
                        renewed = _request_json_with_device("POST", "/uploads/%s/renew" % session_id, {}, state)
                        access_token = renewed["access_token"]
                        _remember_secret(access_token)
                        google_expiry = time.monotonic() + int(renewed.get("expires_in", 3600))
                        break
                    if _is_retryable_error(status):
                        # Check 6-hour minimum before giving up
                        if time.time() - retry_start < 21600:  # 6 hours = 21600 seconds
                            continue  # Keep retrying, not yet 6 hours
                        # 6 hours of continuous failure reached
                        raise UploadError("Google upload failed after 6 hours of continuous HTTP %d errors at offset %d" % (status, offset))
                    # Non-retryable error
                    raise UploadError("Google upload failed (HTTP %d): %s" %
                                      (status, _safe_text(body.decode("utf-8", "replace")[:300])))
                # If we broke out of the inner loop (308 or 401/403), continue outer loop
                # The retry timer was reset implicitly by breaking out
                continue
            if _is_permanent_error(status, body.decode("utf-8", "replace")[:300]):
                raise UploadError("Google upload failed permanently (HTTP %d): %s" %
                                  (status, _safe_text(body.decode("utf-8", "replace")[:300])))
            raise UploadError("Google upload failed (HTTP %d): %s" %
                              (status, _safe_text(body.decode("utf-8", "replace")[:300])))


def upload_detached(session_id, file_path, allow_insecure_file=False):
    path = Path(file_path)
    if not path.is_file() or path.stat().st_size <= 0:
        raise UploadError("Video file does not exist or is empty.")
    status_path = _status_path(session_id)
    existing = local_status(session_id)
    if existing.get("process_alive"):
        print("Upload already running for this session (PID %s)." % existing.get("pid"))
        return 0
    status_path.parent.mkdir(parents=True, exist_ok=True)
    log_file = _log_path(session_id)
    # Ensure log file exists and is writable
    log_file.parent.mkdir(parents=True, exist_ok=True)
    log_file.touch(exist_ok=True)
    if os.name != "nt":
        log_file.chmod(0o600)
    
    worker_args = ["upload", "--session", session_id, "--file", str(path), "--_worker"]
    # For frozen exe, sys.executable IS the exe, so we use the subcommand directly
    # For script mode, use -m tools.ajons_uploader_cli
    if getattr(sys, "frozen", False):
        command = [sys.executable] + worker_args
    else:
        command = [sys.executable, "-m", "tools.ajons_uploader_cli"] + worker_args
    if allow_insecure_file:
        command.append("--allow-insecure-file")
    flags = 0
    # Redirect worker stderr to log file
    stderr_handle = log_file.open("a", encoding="utf-8", errors="replace")
    kwargs = {"stdin": subprocess.DEVNULL, "stdout": subprocess.DEVNULL,
              "stderr": stderr_handle, "close_fds": True}
    if os.name == "nt":
        flags = getattr(subprocess, "DETACHED_PROCESS", 0x00000008) | getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0x00000200)
        kwargs["creationflags"] = flags
    else:
        kwargs["start_new_session"] = True
    process = subprocess.Popen(command, **kwargs)
    # Initial status with file metadata for respawn validation
    size = path.stat().st_size
    mtime_ns = path.stat().st_mtime_ns
    abs_path = str(path.resolve())
    status = {"session_id": session_id, "status": "starting", "pid": process.pid,
              "total_bytes": size, "bytes_uploaded": 0, "percent": 0,
              "speed_bytes_per_second": 0, "eta_seconds": None,
              "last_heartbeat": int(time.time()), "file_name": path.name,
              "file_path": abs_path, "file_size": size, "file_mtime_ns": mtime_ns,
              "retry_count": 0, "last_error": None}
    temp = status_path.with_suffix(".tmp")
    temp.write_text(json.dumps(status, separators=(",", ":")), encoding="utf-8")
    if os.name != "nt":
        os.chmod(temp, 0o600)
    os.replace(temp, status_path)
    
    # Wait for worker to write first heartbeat (5-10 seconds)
    # Skip in test environment where worker is mocked
    if not os.environ.get("AJONS_TESTING"):
        alive, worker_pid = _wait_for_worker_heartbeat(status_path, timeout=10)
        stderr_handle.close()
        if not alive:
            # Worker failed to start - read stderr log
            err = _read_worker_stderr(log_file)
            _write_status(status="failed", error="Worker failed to start: %s" % _safe_text(err or "unknown error"))
            print("Detached uploader failed to start. Check log: %s" % log_file)
            return 1
    else:
        stderr_handle.close()
        worker_pid = process.pid
    print("Detached uploader started (PID %s). Status file: %s" % (worker_pid or process.pid, status_path))
    return 0


def upload_worker(session_id, file_path, allow_insecure_file=False):
    global _ACTIVE_STATUS_PATH
    _ACTIVE_STATUS_PATH = _status_path(session_id)
    log_file = _log_path(session_id)
    locked, lock_file = _acquire_lock(session_id)
    if not locked:
        _write_worker_log(session_id, "Another worker already holds the lock for this session")
        _write_status(status="failed", error="Another worker is already running for this session")
        return 1
    stop_awake = _keep_awake()
    _write_worker_log(session_id, "Worker started (PID %d)" % os.getpid())
    try:
        upload(session_id, file_path, allow_insecure_file)
    except Exception as exc:
        _write_status(status="failed", error=_safe_text(str(exc))[:300])
        _write_worker_log(session_id, "Worker failed: %s" % _safe_text(str(exc)))
        raise
    finally:
        stop_awake()
        _release_lock(lock_file)
        _write_worker_log(session_id, "Worker stopped")


def upload_media(session_id, file_path, allow_insecure_file=False):
    """Upload a local JPEG/PNG straight to YouTube using the claim-scoped token."""
    path = Path(file_path)
    if not path.is_file() or path.stat().st_size <= 0:
        raise UploadError("Image file does not exist or is empty.")
    size = path.stat().st_size
    refresh_token, credential_store = _load_refresh_token(allow_insecure_file)
    state = {"refresh_token": refresh_token, "store": credential_store,
             "allow_file": allow_insecure_file, "device_expiry": 0}
    _renew_device_access(state)
    claim = _request_json_with_device("POST", "/media-uploads/%s/claim" % session_id, {}, state)
    token, upload_url = claim["access_token"], claim["upload_url"]
    _remember_secret(token)
    if size != int(claim["total_bytes"]):
        raise UploadError("Image size differs from the MCP media session. Create a new session with the exact file size.")
    suffix = path.suffix.lower()
    if suffix not in (".jpg", ".jpeg", ".png"):
        raise UploadError("YouTube media uploads require a JPEG or PNG file.")
    mime = "image/png" if suffix == ".png" else "image/jpeg"
    body = path.read_bytes()
    headers = {"Content-Type": mime}
    if claim["media_type"] == "watermark":
        boundary = "ajons-%s" % secrets.token_hex(16)
        metadata = json.dumps(claim.get("settings") or {}, separators=(",", ":")).encode()
        body = (b"--" + boundary.encode() + b"\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n" +
                metadata + b"\r\n--" + boundary.encode() + b"\r\nContent-Type: " + mime.encode() +
                b"\r\n\r\n" + body + b"\r\n--" + boundary.encode() + b"--\r\n")
        headers["Content-Type"] = "multipart/related; boundary=" + boundary
    try:
        status, _headers, response_body = _http_request(
            "POST", upload_url, bearer=token, data=body, headers=headers, timeout=180)
    except UploadError:
        raise
    accepted = (200, 201, 204) if claim["media_type"] == "watermark" else (200, 201)
    if status not in accepted:
        if status in (401, 403):
            raise UploadError("Google denied this media upload. No OAuth scope was widened; review the required YouTube permission before retrying.")
        raise UploadError("Google media upload failed (HTTP %d); sensitive response details were suppressed." % status)
    try:
        google_result = json.loads(response_body) if response_body else {}
    except Exception:
        google_result = {}
    payload = {"google_status": status}
    if claim["media_type"] == "banner":
        payload["banner_url"] = google_result.get("url")
    result = _request_json_with_device(
        "POST", "/media-uploads/%s/complete" % session_id, payload, state)
    if result.get("verified") is False:
        raise UploadError("Google accepted the image, but server verification did not confirm it.")
    print(json.dumps({"type": "media_complete", "media_type": claim["media_type"],
                      "verified": result.get("verified")}, separators=(",", ":")), flush=True)


def _maybe_respawn_worker(session_id, file_path=None, allow_insecure_file=False):
    """If worker is dead and session is not complete, respawn it detached.
    Returns True if respawned, False otherwise. Called from local_status()."""
    status_path = _status_path(session_id)
    try:
        data = json.loads(status_path.read_text(encoding="utf-8"))
    except Exception:
        return False
    st = data.get("status")
    if st in ("completed", "failed"):
        return False
    pid = int(data.get("pid") or 0)
    alive = _pid_alive(pid)
    if alive:
        return False
    # Check respawn limit
    respawn_count = data.get("respawn_count", 0)
    if respawn_count >= _MAX_RESPAWNS:
        _write_status(status="failed", error="Max respawns (%d) exceeded, worker kept dying" % _MAX_RESPAWNS,
                      last_error="Max respawns (%d) exceeded" % _MAX_RESPAWNS)
        return False
    # Validate file metadata from status
    stored_path = data.get("file_path")
    stored_size = data.get("file_size")
    stored_mtime = data.get("file_mtime_ns")
    if not stored_path:
        _write_status(status="failed", error="Cannot respawn: file metadata missing from status",
                      last_error="File metadata missing for respawn")
        return False
    # Check if file exists and matches
    try:
        path = Path(stored_path)
        if not path.is_file():
            _write_status(status="failed", error="Cannot respawn: original file not found at %s" % stored_path,
                          last_error="Original file not found: %s" % stored_path)
            return False
        stat = path.stat()
        if stat.st_size != stored_size:
            _write_status(status="failed", error="Cannot respawn: file size changed (was %d, now %d)" % (stored_size, stat.st_size),
                          last_error="File size mismatch: was %d, now %d" % (stored_size, stat.st_size))
            return False
        if stat.st_mtime_ns != stored_mtime:
            _write_status(status="failed", error="Cannot respawn: file modified (mtime changed)",
                          last_error="File mtime mismatch: was %d, now %d" % (stored_mtime, stat.st_mtime_ns))
            return False
        file_path = str(path)
    except Exception as exc:
        _write_status(status="failed", error="Cannot respawn: file validation error: %s" % _safe_text(str(exc)),
                      last_error="File validation error: %s" % _safe_text(str(exc)))
        return False
    # Acquire lock before spawning
    locked, lock_file = _acquire_lock(session_id)
    if not locked:
        return False  # Another process is handling it
    try:
        # Update status to recovering
        _write_status(status="recovering", respawn_count=respawn_count + 1,
                      last_error="Worker died, respawning (attempt %d/%d)" % (respawn_count + 1, _MAX_RESPAWNS))
        # Spawn new worker
        log_file = _log_path(session_id)
        log_file.parent.mkdir(parents=True, exist_ok=True)
        log_file.touch(exist_ok=True)
        if os.name != "nt":
            log_file.chmod(0o600)
        
        worker_args = ["upload", "--session", session_id, "--file", file_path, "--_worker"]
        if getattr(sys, "frozen", False):
            command = [sys.executable] + worker_args
        else:
            command = [sys.executable, "-m", "tools.ajons_uploader_cli"] + worker_args
        if allow_insecure_file:
            command.append("--allow-insecure-file")
        flags = 0
        stderr_handle = log_file.open("a", encoding="utf-8", errors="replace")
        kwargs = {"stdin": subprocess.DEVNULL, "stdout": subprocess.DEVNULL,
                  "stderr": stderr_handle, "close_fds": True}
        if os.name == "nt":
            flags = getattr(subprocess, "DETACHED_PROCESS", 0x00000008) | getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0x00000200)
            kwargs["creationflags"] = flags
        else:
            kwargs["start_new_session"] = True
        process = subprocess.Popen(command, **kwargs)
        # Update status with new PID
        _write_status(pid=process.pid, status="starting")
        # Wait briefly for heartbeat
        alive, worker_pid = _wait_for_worker_heartbeat(status_path, timeout=10)
        stderr_handle.close()
        if not alive:
            err = _read_worker_stderr(log_file)
            _write_status(status="failed", error="Respawned worker failed to start: %s" % _safe_text(err or "unknown error"))
            _release_lock(lock_file)
            return False
        _write_worker_log(session_id, "Respawned worker started (PID %s)" % (worker_pid or process.pid))
        return True
    except Exception as exc:
        _write_status(status="failed", error="Respawn failed: %s" % _safe_text(str(exc)))
        _release_lock(lock_file)
        return False