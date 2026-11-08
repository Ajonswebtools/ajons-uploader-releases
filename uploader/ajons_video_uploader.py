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
import shutil
from pathlib import Path

try:
    from .security_redaction import redact_text
except Exception:
    from security_redaction import redact_text  # fail closed

BASE_URL = "https://mcp.ajonswebtools.com"
CHUNK = 8 * 1024 * 1024
STORE_SERVICE = "com.ajonswebtools.ajons-uploader"
UPLOADER_VERSION = "1.0.6"
_SENSITIVE_VALUES = set()
_ACTIVE_STATUS_PATH = None
_STATUS_STARTED = None
_STATUS_SAMPLE = None
_STATUS_LOCK = threading.Lock()


def _status_path(session_id):
    safe_id = "".join(ch for ch in str(session_id) if ch.isalnum() or ch in "-_" )[:100]
    return _config_file().parent / "status" / (safe_id + ".json")


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


def local_status(session_id):
    path = _status_path(session_id)
    try:
        result = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {"session_id": session_id, "status": "not_found", "process_alive": False,
                "percent": 0, "bytes_uploaded": 0, "speed_bytes_per_second": None,
                "eta_seconds": None, "last_heartbeat": None}
    pid = int(result.get("pid") or 0)
    try:
        os.kill(pid, 0)
        alive = True
    except (OSError, ValueError):
        alive = False
    result["process_alive"] = alive
    return result


def _keep_awake():
    if os.name == "nt":
        try:
            import ctypes
            ctypes.windll.kernel32.SetThreadExecutionState(0x80000000 | 0x00000001 | 0x00000040)
            return lambda: ctypes.windll.kernel32.SetThreadExecutionState(0x80000000)
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


def _probe_session_position(session_uri, access_token, total_bytes=None, timeout=60):
    try:
        result = _probe(session_uri, access_token, total_bytes or 0)
        return result["offset"] if result else None
    except UploadError:
        return None


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
    status, headers, _body = _http_request("PUT", uri, bearer=token, data=b"", headers={
        "Content-Length": "0", "Content-Range": "bytes */%d" % size,
        "Content-Type": "application/octet-stream",
    })
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


def upload(session_id, file_path, allow_insecure_file=False):
    path = Path(file_path)
    if not path.is_file() or path.stat().st_size <= 0:
        raise UploadError("Video file does not exist or is empty.")
    size = path.stat().st_size
    _write_status(status="starting", total_bytes=size, file_name=path.name,
                  bytes_uploaded=0, percent=0, speed_bytes_per_second=0, eta_seconds=None)
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
                  percent=round((offset / size) * 100, 2), pid=os.getpid())

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
                      speed_bytes_per_second=0, eta_seconds=0)

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
            except UploadError:
                position = _probe(uri, access_token, size) or {"offset": offset, "video_id": None}
                if position["video_id"]:
                    finish(position["video_id"])
                    return
                offset = position["offset"]
                continue
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
                              eta_seconds=(int(remaining / speed) if speed else None))
                continue
            if status in (401, 403):
                renewed = _request_json_with_device("POST", "/uploads/%s/renew" % session_id, {}, state)
                access_token = renewed["access_token"]
                _remember_secret(access_token)
                google_expiry = time.monotonic() + int(renewed.get("expires_in", 3600))
                continue
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
    worker_args = ["upload", "--session", session_id, "--file", str(path), "--_worker"]
    command = ([sys.executable] + worker_args if getattr(sys, "frozen", False) else
               [sys.executable, "-m", "tools.ajons_uploader_cli"] + worker_args)
    if allow_insecure_file:
        command.append("--allow-insecure-file")
    flags = 0
    kwargs = {"stdin": subprocess.DEVNULL, "stdout": subprocess.DEVNULL,
              "stderr": subprocess.DEVNULL, "close_fds": True}
    if os.name == "nt":
        flags = getattr(subprocess, "DETACHED_PROCESS", 0x00000008) | getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0x00000200)
        kwargs["creationflags"] = flags
    else:
        kwargs["start_new_session"] = True
    process = subprocess.Popen(command, **kwargs)
    status = {"session_id": session_id, "status": "starting", "pid": process.pid,
              "total_bytes": path.stat().st_size, "bytes_uploaded": 0, "percent": 0,
              "speed_bytes_per_second": 0, "eta_seconds": None,
              "last_heartbeat": int(time.time()), "file_name": path.name}
    temp = status_path.with_suffix(".tmp")
    temp.write_text(json.dumps(status, separators=(",", ":")), encoding="utf-8")
    if os.name != "nt":
        os.chmod(temp, 0o600)
    os.replace(temp, status_path)
    print("Detached uploader started (PID %s). Status file: %s" % (process.pid, status_path))
    return 0


def upload_worker(session_id, file_path, allow_insecure_file=False):
    global _ACTIVE_STATUS_PATH
    _ACTIVE_STATUS_PATH = _status_path(session_id)
    stop_awake = _keep_awake()
    try:
        upload(session_id, file_path, allow_insecure_file)
    except Exception as exc:
        _write_status(status="failed", error=_safe_text(str(exc))[:300])
        raise
    finally:
        stop_awake()


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
