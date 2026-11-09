# -*- mode: python ; coding: utf-8 -*-
import sys
import os

block_cipher = None

a = Analysis(
    ['uploader/ajons_uploader_cli.py'],
    pathex=['.'],
    binaries=[],
    datas=[('uploader/security_redaction.py', 'uploader')],
    hiddenimports=[
        'uploader.ajons_video_uploader',
        'uploader.ajons_daemon',
        'uploader.ajons_constants',
        'uploader.ajons_utils',
        'uploader.security_redaction',
        'urllib.request',
        'urllib.error',
        'json',
        'getpass',
        'mimetypes',
        'argparse',
        'logging',
        'keyring',
        'keyring.backends.Windows',
        'keyring.backends.macOS',
        'keyring.backends.SecretService',
        'asyncio',
        'dataclasses',
        'uuid',
        'socket',
        'signal',
    ],
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
