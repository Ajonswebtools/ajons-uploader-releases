"""Ajons uploader daemon: single token owner, upload queue, IPC."""
import argparse
import asyncio
import getpass
import json
import os
import platform
import secrets
import signal
import socket
import sys
import tempfile
import threading
import time
import uuid
from contextlib import asynccontextmanager
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Callable, Optional

import keyring
import httpx
from security_redaction import redact_text

from tools.ajons_constants import (
    BASE_URL,
    CHUNK,
    STORE_SERVICE,
    UPLOADER_VERSION,
    UploadError,
)
from tools.ajons_utils import (
    _config_file,
    _keyring,
    _load_refresh_token,
    _request,
    _save_refresh_token,
    _pid_alive,
)


DAEMON_VERSION = "1.1.8"
UPLOADER_VERSION = "1.1.8"
DAEMON_SOCKET_NAME = "ajons-uploader.sock"
DAEMON_INFO_FILE = "daemon.json"
DAEMON_LOCK_FILE = "daemon.lock"
DAEMON_PID_FILE = "daemon.pid"

DEFAULT_CONCURRENCY = 3
TOKEN_RENEW_BEFORE_EXPIRY = 300
HEARTBEAT_INTERVAL = 15
CLIENT_TIMEOUT = 30

# Windows uses TCP localhost with a fixed port file
DAEMON_PORT_FILE = "daemon.port"

@dataclass
class TokenState:
    refresh_token: str
    access_token: Optional[str] = None
    access_expiry: float = 0
    store: tuple = field(default_factory=tuple)
    allow_file: bool = False
    needs_repair: bool = False
    last_renewal_error: Optional[str] = None


@dataclass
class MediaUploadJob:
    job_id: str
    session_id: str
    file_path: str
    media_type: str  # "thumbnail", "banner", "watermark"
    target_video_id: Optional[str] = None
    status: str = "queued"
    created_at: float = field(default_factory=time.time)
    started_at: Optional[float] = None
    completed_at: Optional[float] = None
    bytes_uploaded: int = 0
    total_bytes: int = 0
    speed_bps: float = 0
    eta_seconds: Optional[float] = None
    retry_count: int = 0
    last_error: Optional[str] = None
    cancel_requested: bool = False

    def to_dict(self):
        d = asdict(self)
        return d


@dataclass
class UploadJob:
    job_id: str
    session_id: str
    file_path: str
    title: Optional[str] = None
    description: Optional[str] = None
    tags: Optional[list] = None
    category_id: Optional[str] = None
    privacy_status: str = "private"
    status: str = "queued"
    created_at: float = field(default_factory=time.time)
    started_at: Optional[float] = None
    completed_at: Optional[float] = None
    bytes_uploaded: int = 0
    total_bytes: int = 0
    speed_bps: float = 0
    eta_seconds: Optional[float] = None
    retry_count: int = 0
    last_error: Optional[str] = None
    video_id: Optional[str] = None
    verified: bool = False
    cancel_requested: bool = False
    progress_cb: Optional[Callable] = None

    def to_dict(self):
        d = asdict(self)
        d.pop('progress_cb', None)
        return d


class DaemonClient:
    def __init__(self, socket_path: str):
        self.socket_path = socket_path
        self._lock = threading.Lock()

    def _send(self, request: dict) -> dict:
        # Add secret for Windows TCP connections
        if self.socket_path.startswith("127.0.0.1:"):
            secret = _read_daemon_secret()
            if secret:
                request = dict(request)
                request["secret"] = secret
        with self._lock:
            try:
                if self.socket_path.startswith("127.0.0.1:"):
                    # Windows: TCP connection
                    host, port_str = self.socket_path.split(":")
                    port = int(port_str)
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                        sock.settimeout(CLIENT_TIMEOUT)
                        sock.connect((host, port))
                        sock.sendall(json.dumps(request).encode() + b'\n')
                        response = b''
                        while True:
                            chunk = sock.recv(4096)
                            if not chunk:
                                break
                            response += chunk
                        return json.loads(response.decode())
                else:
                    # Unix: Unix domain socket
                    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
                        sock.settimeout(CLIENT_TIMEOUT)
                        sock.connect(self.socket_path)
                        sock.sendall(json.dumps(request).encode() + b'\n')
                        response = b''
                        while True:
                            chunk = sock.recv(4096)
                            if not chunk:
                                break
                            response += chunk
                        return json.loads(response.decode())
            except Exception as e:
                raise UploadError(f"Daemon communication failed: {e}")

    def submit_upload(self, file_path: str, session_id: str = None, **kwargs) -> dict:
        return self._send({"cmd": "upload", "file_path": file_path, "session_id": session_id, **kwargs})

    def submit_media(self, file_path: str, session_id: str, media_type: str, target_video_id: str = None) -> dict:
        return self._send({
            "cmd": "upload-media",
            "file_path": file_path,
            "session_id": session_id,
            "media_type": media_type,
            "target_video_id": target_video_id
        })

    def status(self, session_id: str = None) -> dict:
        return self._send({"cmd": "status", "session_id": session_id})

    def cancel(self, job_id: str) -> dict:
        return self._send({"cmd": "cancel", "job_id": job_id})

    def stop(self) -> dict:
        return self._send({"cmd": "stop"})

    def pair(self, device_name: str = None) -> dict:
        return self._send({"cmd": "pair", "device_name": device_name})

    def reauthorize(self) -> dict:
        return self._send({"cmd": "reauthorize"})


def _daemon_dir() -> Path:
    if os.name == "nt":
        base = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData/Local"))
        return base / "Ajons" / "uploader"
    return Path.home() / ".local" / "share" / "ajons" / "uploader"


def _daemon_socket_path() -> Path:
    return _daemon_dir() / DAEMON_SOCKET_NAME


def _daemon_info_path() -> Path:
    return _daemon_dir() / DAEMON_INFO_FILE


def _daemon_lock_path() -> Path:
    return _daemon_dir() / DAEMON_LOCK_FILE


def _daemon_pid_path() -> Path:
    return _daemon_dir() / DAEMON_PID_FILE


def _daemon_port_path() -> Path:
    return _daemon_dir() / DAEMON_PORT_FILE


def _write_daemon_info(socket_path: str, pid: int, concurrency: int, port: int = None):
    info = {
        "version": DAEMON_VERSION,
        "socket": socket_path,
        "pid": pid,
        "concurrency": concurrency,
        "started_at": time.time(),
    }
    if port:
        info["port"] = port
    path = _daemon_info_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(info))
    if os.name != "nt":
        os.chmod(tmp, 0o600)
    os.replace(tmp, path)


def _read_daemon_info() -> Optional[dict]:
    path = _daemon_info_path()
    try:
        return json.loads(path.read_text())
    except Exception:
        return None


def _get_daemon_connection() -> Optional[str]:
    """Get the connection string (socket path or host:port) for the running daemon."""
    info = _read_daemon_info()
    if not info:
        return None
    pid = info.get("pid")
    if not pid or not _pid_alive(pid):
        return None
    if os.name == "nt":
        port = info.get("port")
        if port:
            return f"127.0.0.1:{port}"
        # Fallback: read port file
        try:
            port_data = _daemon_port_path().read_text().strip()
            port = int(port_data.split(":")[0])
            return f"127.0.0.1:{port}"
        except Exception:
            return None
    else:
        sock_path = info.get("socket")
        if sock_path and Path(sock_path).exists():
            return sock_path
        return None


def _read_daemon_secret() -> Optional[str]:
    """Read the daemon secret from the port file (Windows only)."""
    if os.name != "nt":
        return None
    try:
        port_data = _daemon_port_path().read_text().strip()
        parts = port_data.split(":")
        if len(parts) == 2:
            return parts[1]
    except Exception:
        pass
    return None


def _clear_daemon_info():
    for p in [_daemon_info_path(), _daemon_lock_path(), _daemon_pid_path(), _daemon_socket_path(), _daemon_port_path()]:
        try:
            p.unlink(missing_ok=True)
        except Exception:
            pass


def _acquire_daemon_lock() -> Optional[int]:
    lock_path = _daemon_lock_path()
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        fd = os.open(str(lock_path), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        os.write(fd, str(os.getpid()).encode())
        os.close(fd)
        return os.getpid()
    except FileExistsError:
        try:
            existing_pid = int(lock_path.read_text().strip())
        except Exception:
            return None
        if existing_pid > 0 and _pid_alive(existing_pid):
            return None
        try:
            lock_path.unlink()
            fd = os.open(str(lock_path), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            os.write(fd, str(os.getpid()).encode())
            os.close(fd)
            return os.getpid()
        except Exception:
            return None


def _is_daemon_running() -> bool:
    return _get_daemon_connection() is not None


def _release_daemon_lock():
    try:
        _daemon_lock_path().unlink(missing_ok=True)
    except Exception:
        pass


def _pid_alive(pid: int) -> bool:
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
                    return exit_code.value == 259
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
            return True
        except OSError:
            return False


def _is_daemon_running() -> bool:
    return _get_daemon_connection() is not None


class TokenManager:
    def __init__(self, allow_file: bool = False):
        self.allow_file = allow_file
        self.state: Optional[TokenState] = None
        self._renewal_lock = asyncio.Lock()
        self._renewal_task: Optional[asyncio.Task] = None

    async def initialize(self) -> bool:
        try:
            refresh_token, store = _load_refresh_token(self.allow_file)
            self.state = TokenState(refresh_token=refresh_token, store=store, allow_file=self.allow_file)
            await self._renew_access_token()
            return True
        except UploadError as e:
            if "No paired device" in str(e):
                return False
            raise

    async def _renew_access_token(self) -> str:
        async with self._renewal_lock:
            if not self.state:
                raise UploadError("Token manager not initialized")
            if self.state.needs_repair:
                raise UploadError("Device credential revoked; re-pair required")

            now = time.monotonic()
            if self.state.access_token and now < self.state.access_expiry - 60:
                return self.state.access_token

            try:
                status, headers, body = _request(
                    "POST", BASE_URL + "/device/token",
                    payload={"refresh_token": self.state.refresh_token},
                    timeout=30
                )
                if status != 200:
                    err = json.loads(body).get("error", "unknown")
                    if err in ("invalid_grant", "access_denied"):
                        self.state.needs_repair = True
                        self.state.last_renewal_error = f"Server rejected refresh token: {err}"
                    raise UploadError(f"Token renewal failed: {err}")

                result = json.loads(body)
                new_refresh = result["refresh_token"]
                new_access = result["access_token"]
                expires_in = int(result.get("expires_in", 600))

                self.state.refresh_token = new_refresh
                self.state.access_token = new_access
                self.state.access_expiry = time.monotonic() + expires_in
                self.state.last_renewal_error = None

                _save_refresh_token(new_refresh, self.state.store, self.state.allow_file)
                return new_access

            except Exception as e:
                if "invalid_grant" in str(e) or "access_denied" in str(e):
                    self.state.needs_repair = True
                    self.state.last_renewal_error = str(e)
                raise

    def get_access_token(self) -> Optional[str]:
        if not self.state or not self.state.access_token:
            return None
        if time.monotonic() >= self.state.access_expiry - 60:
            return None
        return self.state.access_token

    async def ensure_valid_token(self) -> str:
        token = self.get_access_token()
        if token:
            return token
        return await self._renew_access_token()

    async def start_proactive_renewal(self):
        if self._renewal_task:
            return
        async def renewal_loop():
            while self.state and not self.state.needs_repair:
                await asyncio.sleep(30)
                if self.state and not self.state.needs_repair:
                    if time.monotonic() >= self.state.access_expiry - TOKEN_RENEW_BEFORE_EXPIRY:
                        try:
                            await self._renew_access_token()
                        except Exception:
                            pass
        self._renewal_task = asyncio.create_task(renewal_loop())

    def stop_proactive_renewal(self):
        if self._renewal_task:
            self._renewal_task.cancel()
            self._renewal_task = None


class UploadQueue:
    def __init__(self, concurrency: int = DEFAULT_CONCURRENCY):
        self.concurrency = concurrency
        self.jobs: dict[str, UploadJob] = {}
        self._running = 0
        self._semaphore: Optional[asyncio.Semaphore] = None
        self._worker_tasks: list[asyncio.Task] = []

    async def start(self, token_manager: TokenManager):
        self._semaphore = asyncio.Semaphore(self.concurrency)
        self._token_manager = token_manager

    async def stop(self):
        for job in self.jobs.values():
            job.cancel_requested = True
        for task in self._worker_tasks:
            task.cancel()
        await asyncio.gather(*self._worker_tasks, return_exceptions=True)

    def submit(self, job: UploadJob) -> str:
        self.jobs[job.job_id] = job
        return job.job_id

    def get_job(self, job_id: str) -> Optional[UploadJob]:
        return self.jobs.get(job_id)

    def list_jobs(self) -> list[dict]:
        return [j.to_dict() for j in self.jobs.values()]

    async def process(self, job: UploadJob):
        async with self._semaphore:
            self._running += 1
            job.status = "claiming"
            job.started_at = time.monotonic()
            try:
                await self._run_job(job)
            except asyncio.CancelledError:
                job.status = "cancelled"
                raise
            except Exception as e:
                job.status = "failed"
                job.last_error = str(e)
                job.completed_at = time.monotonic()
            finally:
                self._running -= 1

    async def _run_job(self, job: UploadJob):
        token = await self._token_manager.ensure_valid_token()
        if not token:
            raise UploadError("No valid device credential; re-pair required")

        job.status = "uploading"
        path = Path(job.file_path)
        size = path.stat().st_size
        claim_resp = await _json_request_with_token("POST", f"/uploads/{job.session_id}/claim",
                                                    {"declared_size": size}, token)
        uri = claim_resp["upload_uri"]
        access_token = claim_resp["access_token"]
        google_expiry = time.monotonic() + int(claim_resp.get("expires_in", 3600))

        # D5: Compare local file size with session total_bytes from the server
        # before sending any bytes. Reject at once on mismatch.
        server_total = claim_resp.get("total_bytes")
        if server_total is not None and int(server_total) != size:
            raise UploadError(
                "Session size mismatch: local %d, server %d" % (size, int(server_total)))

        job.total_bytes = size

        position = _probe_with_token(uri, access_token, size)
        offset = position.get("offset", 0)
        if position.get("video_id"):
            job.video_id = position["video_id"]
            job.verified = True
            job.status = "done"
            job.completed_at = time.monotonic()
            job.bytes_uploaded = size
            token = await self._token_manager.ensure_valid_token()
            if not token:
                raise UploadError("Lost device credential during upload")
            await _complete_with_token(job.session_id, job.video_id, token)
            return
        job.bytes_uploaded = offset

        with path.open("rb") as f:
            while offset < size and not job.cancel_requested:
                if time.monotonic() >= google_expiry - 60:
                    token = await self._token_manager.ensure_valid_token()
                    if not token:
                        raise UploadError("Lost device credential during upload")
                    renewed = await _json_request_with_token("POST", f"/uploads/{job.session_id}/renew", {}, token)
                    access_token = renewed["access_token"]
                    google_expiry = time.monotonic() + int(renewed.get("expires_in", 3600))

                f.seek(offset)
                chunk = f.read(min(CHUNK, size - offset))
                end = offset + len(chunk) - 1

                # D6: Run the blocking HTTP request in a thread so the daemon
                # event loop stays responsive to status requests during long
                # chunk uploads (timeout=180 would otherwise block for 3 min).
                status, headers, body = await asyncio.to_thread(
                    _request,
                    "PUT", uri, bearer=access_token, data=chunk, headers={
                        "Content-Length": str(len(chunk)),
                        "Content-Range": f"bytes {offset}-{end}/{size}",
                        "Content-Type": "video/mp4",
                    }, timeout=180
                )

                if status in (200, 201):
                    try:
                        video_id = json.loads(body).get("id")
                    except Exception:
                        video_id = None
                    if video_id:
                        job.video_id = video_id
                        job.verified = True
                        job.status = "done"
                        job.completed_at = time.monotonic()
                        job.bytes_uploaded = size
                        token = await self._token_manager.ensure_valid_token()
                        if not token:
                            raise UploadError("Lost device credential during upload")
                        await _complete_with_token(job.session_id, video_id, token)
                        return

                if status == 308:
                    range_header = headers.get("Range", "")
                    try:
                        offset = int(range_header.rsplit("-", 1)[1]) + 1 if range_header else 0
                    except Exception:
                        position = _probe_with_token(uri, access_token, size)
                        offset = position.get("offset", 0)
                    job.bytes_uploaded = offset
                    token = await self._token_manager.ensure_valid_token()
                    if not token:
                        raise UploadError("Lost device credential during upload")
                    await _progress_with_token(job.session_id, offset, token)
                    continue

                if status in (401, 403):
                    token = await self._token_manager.ensure_valid_token()
                    if not token:
                        raise UploadError("Device credential invalidated during upload")
                    continue

                if status in (500, 502, 503, 504):
                    job.retry_count += 1
                    await asyncio.sleep(min(5 * (2 ** (job.retry_count - 1)), 300))
                    continue

                raise UploadError(f"Upload failed: HTTP {status}")

        if job.cancel_requested:
            job.status = "cancelled"
        elif job.status != "done":
            job.status = "failed"
            job.last_error = "Upload incomplete"


async def _json_request_with_token(method: str, path: str, payload: dict, token: str) -> dict:
    status, headers, body = await asyncio.to_thread(
        _request, method, BASE_URL + path, payload=payload, bearer=token, timeout=30)
    if status >= 400:
        err = json.loads(body).get("error", "request rejected") if body else "request rejected"
        raise UploadError(f"Server error: {err}")
    return json.loads(body) if body else {}


def _probe_with_token(uri: str, token: str, size: int) -> dict:
    try:
        status, headers, body = _request("PUT", uri, bearer=token, data=b"", headers={
            "Content-Length": "0", "Content-Range": f"bytes */{size}",
            "Content-Type": "application/octet-stream",
        }, timeout=30)
    except Exception:
        return {}
    if status == 308:
        return {"offset": _parse_range_header(headers.get("Range")) or 0, "video_id": None}
    if status in (200, 201):
        try:
            return {"offset": size, "video_id": json.loads(body).get("id")}
        except Exception:
            return {"offset": size, "video_id": None}
    return {}


def _parse_range_header(value: str) -> Optional[int]:
    try:
        _, part = value.split("=", 1)
        _start, end = part.split("-", 1)
        return int(end) + 1
    except Exception:
        return None


async def _progress_with_token(session_id: str, bytes_uploaded: int, token: str):
    await _json_request_with_token("POST", f"/uploads/{session_id}/progress", {"bytes_uploaded": bytes_uploaded}, token)


async def _complete_with_token(session_id: str, video_id: str, token: str):
    await _json_request_with_token("POST", f"/uploads/{session_id}/complete", {"video_id": video_id}, token)


async def _claim_media_with_token(session_id: str, media_type: str, file_size: int, token: str) -> dict:
    """Claim a media upload session with the server."""
    return await _json_request_with_token("POST", f"/uploads/{session_id}/media/claim", {
        "media_type": media_type,
        "declared_size": file_size
    }, token)


async def _complete_media_with_token(session_id: str, media_type: str, token: str) -> dict:
    """Complete a media upload session with the server."""
    return await _json_request_with_token("POST", f"/uploads/{session_id}/media/complete", {
        "media_type": media_type
    }, token)


class MediaUploadQueue:
    def __init__(self, concurrency: int = 1):
        self.concurrency = concurrency
        self.jobs: dict[str, MediaUploadJob] = {}
        self._running = 0
        self._semaphore: Optional[asyncio.Semaphore] = None
        self._worker_tasks: list[asyncio.Task] = []

    async def start(self, token_manager: TokenManager):
        self._semaphore = asyncio.Semaphore(self.concurrency)
        self._token_manager = token_manager

    async def stop(self):
        for job in self.jobs.values():
            job.cancel_requested = True
        for task in self._worker_tasks:
            task.cancel()
        await asyncio.gather(*self._worker_tasks, return_exceptions=True)

    def submit(self, job: MediaUploadJob) -> str:
        self.jobs[job.job_id] = job
        return job.job_id

    def get_job(self, job_id: str) -> Optional[MediaUploadJob]:
        return self.jobs.get(job_id)

    def list_jobs(self) -> list[dict]:
        return [j.to_dict() for j in self.jobs.values()]

    async def process(self, job: MediaUploadJob):
        async with self._semaphore:
            self._running += 1
            job.status = "claiming"
            job.started_at = time.monotonic()
            try:
                await self._run_media_job(job)
            except asyncio.CancelledError:
                job.status = "cancelled"
                raise
            except Exception as e:
                job.status = "failed"
                job.last_error = str(e)
                job.completed_at = time.monotonic()
            finally:
                self._running -= 1

    async def _run_media_job(self, job: MediaUploadJob):
        token = await self._token_manager.ensure_valid_token()
        if not token:
            raise UploadError("No valid device credential; re-pair required")

        job.status = "uploading"
        path = Path(job.file_path)
        size = path.stat().st_size
        
        # Claim media upload session
        claim_resp = await _claim_media_with_token(job.session_id, job.media_type, size, token)
        uri = claim_resp["upload_url"]
        access_token = claim_resp["access_token"]
        google_expiry = time.monotonic() + int(claim_resp.get("expires_in", 3600))

        job.total_bytes = size

        # Probe for existing upload position
        position = _probe_with_token(uri, access_token, size)
        offset = position.get("offset", 0)
        
        job.bytes_uploaded = offset

        with path.open("rb") as f:
            while offset < size and not job.cancel_requested:
                if time.monotonic() >= google_expiry - 60:
                    token = await self._token_manager.ensure_valid_token()
                    if not token:
                        raise UploadError("Lost device credential during upload")
                    # Re-claim to get fresh token (media uploads don't have renew endpoint)
                    claim_resp = await _claim_media_with_token(job.session_id, job.media_type, size, token)
                    uri = claim_resp["upload_url"]
                    access_token = claim_resp["access_token"]
                    google_expiry = time.monotonic() + int(claim_resp.get("expires_in", 3600))

                f.seek(offset)
                chunk = f.read(min(CHUNK, size - offset))
                end = offset + len(chunk) - 1

                status, headers, body = await asyncio.to_thread(
                    _request,
                    "PUT", uri, bearer=access_token, data=chunk, headers={
                        "Content-Length": str(len(chunk)),
                        "Content-Range": f"bytes {offset}-{end}/{size}",
                        "Content-Type": "application/octet-stream",
                    }, timeout=180
                )

                if status in (200, 201):
                    job.bytes_uploaded = size
                    job.status = "done"
                    job.completed_at = time.monotonic()
                    # Complete the media upload
                    token = await self._token_manager.ensure_valid_token()
                    if not token:
                        raise UploadError("Lost device credential during upload")
                    await _complete_media_with_token(job.session_id, job.media_type, token)
                    return

                if status == 308:
                    range_header = headers.get("Range", "")
                    try:
                        offset = int(range_header.rsplit("-", 1)[1]) + 1 if range_header else 0
                    except Exception:
                        position = _probe_with_token(uri, access_token, size)
                        offset = position.get("offset", 0)
                    job.bytes_uploaded = offset
                    token = await self._token_manager.ensure_valid_token()
                    if not token:
                        raise UploadError("Lost device credential during upload")
                    continue

                if status in (401, 403):
                    token = await self._token_manager.ensure_valid_token()
                    if not token:
                        raise UploadError("Device credential invalidated during upload")
                    continue

                if status in (500, 502, 503, 504):
                    job.retry_count += 1
                    await asyncio.sleep(min(5 * (2 ** (job.retry_count - 1)), 300))
                    continue

                raise UploadError(f"Media upload failed: HTTP {status}")

        if job.cancel_requested:
            job.status = "cancelled"
        elif job.status != "done":
            job.status = "failed"
            job.last_error = "Media upload incomplete"


class DaemonServer:
    def __init__(self, concurrency: int = DEFAULT_CONCURRENCY, allow_file: bool = False):
        self.concurrency = concurrency
        self.allow_file = allow_file
        self.socket_path = str(_daemon_socket_path())
        self.port = None
        self.secret = None
        self.token_manager = TokenManager(allow_file)
        self.queue = UploadQueue(concurrency)
        self.media_queue = MediaUploadQueue(1)  # Media uploads are sequential
        self._server: Optional[asyncio.Server] = None
        self._running = False
        self.stop_event: Optional[asyncio.Event] = None

    async def start(self):
        if os.name != "nt":
            # Unix: use Unix domain socket
            try:
                os.unlink(self.socket_path)
            except FileNotFoundError:
                pass

            self._server = await asyncio.start_unix_server(
                self._handle_client, path=self.socket_path
            )
            os.chmod(self.socket_path, 0o600)
        else:
            # Windows: use TCP localhost with random port and secret
            self.secret = secrets.token_urlsafe(32)
            self._server = await asyncio.start_server(
                self._handle_client, host="127.0.0.1", port=0
            )
            # Get the assigned port
            sockets = self._server.sockets
            if sockets:
                self.port = sockets[0].getsockname()[1]
                _daemon_port_path().write_text(f"{self.port}:{self.secret}")
                self.socket_path = f"127.0.0.1:{self.port}"

        initialized = await self.token_manager.initialize()
        if not initialized:
            print("No paired device found. Run 'ajons-uploader pair' first to enable uploads.", file=sys.stderr)

        await self.token_manager.start_proactive_renewal()
        await self.queue.start(self.token_manager)
        await self.media_queue.start(self.token_manager)

        _write_daemon_info(self.socket_path, os.getpid(), self.concurrency, self.port)
        _daemon_pid_path().write_text(str(os.getpid()))
        self._running = True
        print(f"Daemon started on {self.socket_path}", file=sys.stderr)
        return True

    async def stop(self):
        self._running = False
        await self.queue.stop()
        await self.media_queue.stop()
        self.token_manager.stop_proactive_renewal()
        if self._server:
            self._server.close()
            await self._server.wait_closed()
        if os.name == "nt":
            try:
                _daemon_port_path().unlink(missing_ok=True)
            except Exception:
                pass
        _release_daemon_lock()
        _clear_daemon_info()
        print("Daemon stopped", file=sys.stderr)
        if self.stop_event:
            self.stop_event.set()

    async def _handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        try:
            data = await reader.read(65536)
            if not data:
                return
            request = json.loads(data.decode())
            # Validate secret for Windows TCP connections
            if os.name == "nt" and self.secret:
                provided_secret = request.get("secret")
                if provided_secret != self.secret:
                    response = {"error": "Invalid or missing daemon secret"}
                    writer.write(json.dumps(response).encode() + b'\n')
                    await writer.drain()
                    return
            response = await self._process_request(request)
            writer.write(json.dumps(response).encode() + b'\n')
            await writer.drain()
        except Exception as e:
            try:
                writer.write(json.dumps({"error": str(e)}).encode() + b'\n')
                await writer.drain()
            except Exception:
                pass
        finally:
            writer.close()
            await writer.wait_closed()

    async def _process_request(self, request: dict) -> dict:
        cmd = request.get("cmd")
        if cmd == "upload":
            return await self._handle_upload(request)
        elif cmd == "upload-media":
            return await self._handle_upload_media(request)
        elif cmd == "status":
            return await self._handle_status(request)
        elif cmd == "cancel":
            return await self._handle_cancel(request)
        elif cmd == "stop":
            return await self._handle_stop()
        elif cmd == "pair":
            return await self._handle_pair(request)
        elif cmd == "reauthorize":
            return await self._handle_reauthorize()
        return {"error": f"Unknown command: {cmd}"}

    async def _handle_upload(self, request: dict) -> dict:
        file_path = request.get("file_path")
        session_id = request.get("session_id")
        if not file_path or not Path(file_path).is_file():
            return {"error": "File not found"}

        if not session_id:
            return {"error": "session_id required"}

        # D4: Refuse to queue a second job for a session that already has one
        # queued, claiming, uploading, or done. Return the existing job ID.
        for job in self.queue.list_jobs():
            if job["session_id"] == session_id and job["status"] in (
                "queued", "claiming", "uploading", "done"
            ):
                return {"job_id": job["job_id"], "status": job["status"], "existing": True}

        job = UploadJob(
            job_id=uuid.uuid4().hex[:12],
            session_id=session_id,
            file_path=file_path,
            title=request.get("title"),
            description=request.get("description"),
            tags=request.get("tags"),
            category_id=request.get("category_id"),
            privacy_status=request.get("privacy_status", "private"),
        )
        self.queue.submit(job)
        asyncio.create_task(self.queue.process(job))
        return {"job_id": job.job_id, "status": "queued"}

    async def _handle_upload_media(self, request: dict) -> dict:
        file_path = request.get("file_path")
        session_id = request.get("session_id")
        media_type = request.get("media_type")
        target_video_id = request.get("target_video_id")
        
        if not file_path or not Path(file_path).is_file():
            return {"error": "File not found"}

        if not session_id:
            return {"error": "session_id required"}

        if not media_type or media_type not in ("thumbnail", "banner", "watermark"):
            return {"error": "Invalid media_type; must be thumbnail, banner, or watermark"}

        # Check for existing media job for this session/media_type
        for job in self.media_queue.list_jobs():
            if job["session_id"] == session_id and job.get("media_type") == media_type and job["status"] in (
                "queued", "claiming", "uploading", "done"
            ):
                return {"job_id": job["job_id"], "status": job["status"], "existing": True}

        job = MediaUploadJob(
            job_id=uuid.uuid4().hex[:12],
            session_id=session_id,
            file_path=file_path,
            media_type=media_type,
            target_video_id=target_video_id,
        )
        self.media_queue.submit(job)
        asyncio.create_task(self.media_queue.process(job))
        return {"job_id": job.job_id, "status": "queued"}

    async def _handle_status(self, request: dict) -> dict:
        session_id = request.get("session_id")
        jobs = self.queue.list_jobs()
        media_jobs = self.media_queue.list_jobs()
        if session_id:
            jobs = [j for j in jobs if j["session_id"] == session_id]
            media_jobs = [j for j in media_jobs if j["session_id"] == session_id]

        token_valid = self.token_manager.state is not None and not self.token_manager.state.needs_repair
        return {
            "daemon_version": DAEMON_VERSION,
            "token_valid": token_valid,
            "needs_repair": self.token_manager.state.needs_repair if self.token_manager.state else True,
            "last_renewal_error": self.token_manager.state.last_renewal_error if self.token_manager.state else None,
            "concurrency": self.concurrency,
            "running": self.queue._running + self.media_queue._running,
            "jobs": jobs,
            "media_jobs": media_jobs,
        }

    async def _handle_cancel(self, request: dict) -> dict:
        job_id = request.get("job_id")
        job = self.queue.get_job(job_id)
        if not job:
            job = self.media_queue.get_job(job_id)
        if not job:
            return {"error": "Job not found"}
        job.cancel_requested = True
        return {"cancelled": True}

    async def _handle_stop(self) -> dict:
        if self.stop_event:
            self.stop_event.set()
        return {"stopping": True}

    async def _handle_pair(self, request: dict) -> dict:
        device_name = request.get("device_name") or platform.node() or "Ajons uploader"
        try:
            response = await _json_request_with_token("POST", "/device/code", {
                "device_name": device_name,
                "os": platform.platform()[:80],
            }, "")
        except UploadError as e:
            return {"error": str(e)}

        user_code = response["user_code"]
        verification_url = response.get("verification_uri_complete") or response["verification_uri"]
        device_code = response["device_code"]
        interval = int(response.get("interval", 5))
        deadline = time.monotonic() + int(response.get("expires_in", 600))

        print(f"Code: {user_code}")
        print(f"URL: {verification_url}")

        while time.monotonic() < deadline:
            await asyncio.sleep(interval)
            try:
                result = await _json_request_with_token("POST", "/device/token", {"device_code": device_code}, "")
            except UploadError as e:
                msg = str(e)
                if "authorization_pending" in msg:
                    continue
                if "slow_down" in msg:
                    interval += 5
                    continue
                return {"error": msg}

            refresh_token = result.get("refresh_token")
            if not refresh_token:
                return {"error": "Pairing response missing refresh token"}

            store = _keyring()
            if store:
                store.set_password(STORE_SERVICE, "device-refresh", refresh_token)
            else:
                _save_refresh_token(refresh_token, ("file", _config_file()), allow_file=True)

            self.token_manager = TokenManager(self.allow_file)
            await self.token_manager.initialize()
            await self.token_manager.start_proactive_renewal()
            return {"paired": True}

        return {"error": "Pairing timed out"}

    async def _handle_reauthorize(self) -> dict:
        if self.token_manager.state:
            self.token_manager.state.needs_repair = False
            self.token_manager.state.last_renewal_error = None
            try:
                await self.token_manager._renew_access_token()
                return {"reauthorized": True}
            except Exception as e:
                return {"error": str(e)}
        return {"error": "No device paired"}


async def run_daemon(concurrency: int = DEFAULT_CONCURRENCY, allow_file: bool = False):
    pid = _acquire_daemon_lock()
    if not pid:
        info = _read_daemon_info()
        if info and _pid_alive(info.get("pid", 0)):
            print("Daemon already running", file=sys.stderr)
            return 1
        print("Stale lock detected, taking over", file=sys.stderr)

    server = DaemonServer(concurrency, allow_file)
    if not await server.start():
        _release_daemon_lock()
        return 1

    loop = asyncio.get_event_loop()
    stop_event = asyncio.Event()
    server.stop_event = stop_event

    def signal_handler():
        stop_event.set()

    for sig in (signal.SIGTERM, signal.SIGINT):
        try:
            loop.add_signal_handler(sig, signal_handler)
        except NotImplementedError:
            pass

    await stop_event.wait()
    await server.stop()
    return 0


def daemon_status() -> dict:
    conn = _get_daemon_connection()
    if not conn:
        return {"running": False}

    client = DaemonClient(conn)
    try:
        return client.status()
    except Exception as e:
        return {"running": True, "error": f"Daemon unresponsive: {e}"}


def daemon_submit_upload(file_path: str, session_id: str, **kwargs) -> dict:
    conn = _get_daemon_connection()
    if not conn:
        return {"error": "Daemon not running"}
    client = DaemonClient(conn)
    return client.submit_upload(file_path, session_id, **kwargs)


def daemon_submit_media(file_path: str, session_id: str, media_type: str, target_video_id: str = None) -> dict:
    conn = _get_daemon_connection()
    if not conn:
        return {"error": "Daemon not running"}
    client = DaemonClient(conn)
    return client.submit_media(file_path, session_id, media_type, target_video_id)


def daemon_cancel(job_id: str) -> dict:
    conn = _get_daemon_connection()
    if not conn:
        return {"error": "Daemon not running"}
    client = DaemonClient(conn)
    return client.cancel(job_id)


def daemon_stop() -> dict:
    conn = _get_daemon_connection()
    if not conn:
        return {"stopped": True}
    client = DaemonClient(conn)
    return client.stop()


def daemon_pair(device_name: str = None) -> dict:
    conn = _get_daemon_connection()
    if not conn:
        return {"error": "Daemon not running"}
    client = DaemonClient(conn)
    return client.pair(device_name)


def daemon_reauthorize() -> dict:
    conn = _get_daemon_connection()
    if not conn:
        return {"error": "Daemon not running"}
    client = DaemonClient(conn)
    return client.reauthorize()


def _ensure_daemon_running(allow_file: bool = False) -> bool:
    if _get_daemon_connection():
        return True
    import subprocess
    try:
        if getattr(sys, "frozen", False):
            cmd = [sys.executable, "serve", "--concurrency", str(DEFAULT_CONCURRENCY)]
        else:
            cmd = [sys.executable, "-m", "tools.ajons_daemon", "serve", "--concurrency", str(DEFAULT_CONCURRENCY)]
        if allow_file:
            cmd.append("--allow-insecure-file")
        subprocess.Popen(cmd, start_new_session=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for _ in range(20):
            time.sleep(0.25)
            if _is_daemon_running():
                return True
    except Exception:
        pass
    return False