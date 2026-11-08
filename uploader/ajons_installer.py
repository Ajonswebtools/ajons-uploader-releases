#!/usr/bin/env python3
"""Ajons Uploader Automatic Installer - Cross-platform installation helper."""
import argparse
import hashlib
import json
import os
import platform
import stat
import subprocess
import sys
import tempfile
import urllib.request
from pathlib import Path


__version__ = "1.0.0"

REPO_OWNER = "Ajonswebtools"
REPO_NAME = "ajons-mcp-server"
GITHUB_RELEASES_URL = "https://github.com/Ajonswebtools/ajons-uploader-releases/releases/latest/download"


PLATFORM_ASSETS = {
    ("Windows", "AMD64"): ("ajons-uploader-windows-x64.exe", "ajons-uploader-windows-x64.exe"),
    ("Windows", "x86_64"): ("ajons-uploader-windows-x64.exe", "ajons-uploader-windows-x64.exe"),
    ("Linux", "x86_64"): ("ajons-uploader-linux-x64", "ajons-uploader"),
    ("Linux", "amd64"): ("ajons-uploader-linux-x64", "ajons-uploader"),
    ("Darwin", "arm64"): ("ajons-uploader-macos-arm64", "ajons-uploader"),
    ("Darwin", "aarch64"): ("ajons-uploader-macos-arm64", "ajons-uploader"),
    ("Darwin", "x86_64"): ("ajons-uploader-macos-intel", "ajons-uploader"),
}


def get_install_dir():
    """Get platform-appropriate installation directory."""
    system = platform.system()
    if system == "Windows":
        base = os.environ.get("LOCALAPPDATA", os.path.expanduser("~\\AppData\\Local"))
        return Path(base) / "Ajons" / "uploader"
    else:
        base = os.path.expanduser("~/.local/share")
        return Path(base) / "ajons" / "uploader"


def get_executable_name():
    system = platform.system()
    if system == "Windows":
        return "ajons-uploader.exe"
    return "ajons-uploader"


def detect_platform():
    system = platform.system()
    machine = platform.machine()
    key = (system, machine)
    if key not in PLATFORM_ASSETS:
        raise ValueError(f"Unsupported platform: {system} {machine}")
    asset_name, exec_name = PLATFORM_ASSETS[key]
    return system, machine, asset_name, exec_name


def calculate_sha256(filepath):
    sha256_hash = hashlib.sha256()
    with open(filepath, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()


def download_file(url, dest_path):
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'Ajons-Uploader-Installer/1.0'})
        with urllib.request.urlopen(req, timeout=300) as response:
            with open(dest_path, 'wb') as out_file:
                out_file.write(response.read())
        return True
    except Exception as e:
        print(f"Download failed: {e}", file=sys.stderr)
        return False


def install_uploader(force=False):
    try:
        system, machine, asset_name, exec_name = detect_platform()
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    
    install_dir = get_install_dir()
    install_dir.mkdir(parents=True, exist_ok=True)
    install_path = install_dir / exec_name
    
    # Check existing installation
    if install_path.exists() and not force:
        try:
            result = subprocess.run([str(install_path), "--version"], 
                                  capture_output=True, timeout=5)
            if result.returncode == 0:
                print(f"Already installed: {result.stdout.decode().strip()}")
                print(f"Location: {install_path}")
                return 0
        except:
            pass
    
    print(f"Installing Ajons uploader for {system} {machine}...")
    print(f"Installing to: {install_path}")
    
    # Download binary
    binary_url = f"{GITHUB_RELEASES_URL}/{asset_name}"
    checksum_url = f"{GITHUB_RELEASES_URL}/{asset_name}.sha256"
    
    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir_path = Path(tmpdir)
        tmp_binary = tmpdir_path / asset_name
        tmp_checksum = tmpdir_path / f"{asset_name}.sha256"
        
        print("Downloading binary...")
        if not download_file(binary_url, tmp_binary):
            print("Error: Failed to download binary. Check if release exists.", file=sys.stderr)
            return 1
        
        print("Downloading checksum...")
        if not download_file(checksum_url, tmp_checksum):
            print("Error: Failed to download checksum.", file=sys.stderr)
            return 1
        
        # Verify checksum
        print("Verifying checksum...")
        with open(tmp_checksum) as f:
            checksum_content = f.read().strip()
        expected_checksum = checksum_content.split()[0].lower()
        
        actual_checksum = calculate_sha256(tmp_binary).lower()
        
        if actual_checksum != expected_checksum:
            print(f"Error: Checksum verification failed!", file=sys.stderr)
            print(f"Expected: {expected_checksum}", file=sys.stderr)
            print(f"Actual: {actual_checksum}", file=sys.stderr)
            return 1
        
        print("Checksum verified successfully")
        
        # Install
        import shutil
        shutil.copy2(tmp_binary, install_path)
        
        # Set executable permissions on Unix
        if system != "Windows":
            st = os.stat(install_path)
            os.chmod(install_path, st.st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        
        print("Installation complete")
    
    # Verify installation
    try:
        result = subprocess.run([str(install_path), "--version"], 
                              capture_output=True, timeout=5)
        if result.returncode == 0:
            print(f"Verified: {result.stdout.decode().strip()}")
            return 0
        else:
            print("Warning: Installation completed but verification failed", file=sys.stderr)
            return 1
    except Exception as e:
        print(f"Warning: Could not verify installation: {e}", file=sys.stderr)
        return 1


def main():
    parser = argparse.ArgumentParser(description="Ajons Uploader Installer")
    parser.add_argument("--force", action="store_true", help="Force reinstall even if exists")
    parser.add_argument("--version", action="version", version=f"ajons-installer {__version__}")
    args = parser.parse_args()
    
    return install_uploader(force=args.force)


if __name__ == "__main__":
    sys.exit(main())
