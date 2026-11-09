# -*- mode: python ; coding: utf-8 -*-
import sys
import os

# When building from releases repo root, uploader dir is at ./uploader
# When building from uploader repo root, uploader dir is at .
# Detect which case we're in by checking if 'tools' package exists in current dir
if os.path.isdir('tools'):
    UPLOADER_DIR = '.'
else:
    UPLOADER_DIR = 'uploader'

# Ensure uploader directory is on Python path for module discovery
sys.path.insert(0, os.path.abspath(UPLOADER_DIR))

block_cipher = None

a = Analysis(
    ['ajons_uploader_cli.py'],
    pathex=[os.path.abspath(UPLOADER_DIR)],
    binaries=[],
    datas=[('security_redaction.py', '.')],
    hiddenimports=[
        'tools.ajons_video_uploader',
        'tools.ajons_daemon',
        'tools.ajons_constants',
        'tools.ajons_utils',
        'tools.security_redaction',
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
