# -*- mode: python ; coding: utf-8 -*-
import sys
import os

from PyInstaller.utils.hooks import collect_submodules

# When building from releases repo root, uploader dir is at ./uploader.
# The entry script and the tools package live under ./uploader.
UPLOADER_DIR = 'uploader'

block_cipher = None

a = Analysis(
    ['ajons_uploader_cli.py'],
    pathex=[os.path.abspath(UPLOADER_DIR)],
    binaries=[],
    datas=[],
    hiddenimports=[
        'security_redaction',
        'keyring',
        'keyring.backends.Windows',
        'keyring.backends.macOS',
        'keyring.backends.SecretService',
        'win32ctypes',
    ] + collect_submodules('tools'),
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='ajons-uploader',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
