"""Tests for uploader installer helpers (public distribution copy)."""
import os
import platform
import tempfile
from pathlib import Path

from uploader import ajons_installer


def test_platform_detection():
    try:
        result = ajons_installer.detect_platform()
        assert len(result) == 4
    except ValueError:
        pass


def test_install_dir():
    install_dir = ajons_installer.get_install_dir()
    assert isinstance(install_dir, Path)
    assert len(str(install_dir)) > 0


def test_executable_name():
    exec_name = ajons_installer.get_executable_name()
    assert isinstance(exec_name, str) and exec_name


def test_calculate_sha256():
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(b"test data")
        fname = f.name
    try:
        checksum = ajons_installer.calculate_sha256(fname)
        assert len(checksum) == 64
    finally:
        os.unlink(fname)
