# -*- mode: python ; coding: utf-8 -*-

block_cipher = None

datas = [
    ("tools/librespeed", "tools/librespeed"),
    ("tools/iperf3", "tools/iperf3"),
    ("THIRD_PARTY_NOTICES.md", "."),
    ("README.md", "."),
]

hiddenimports = [
    "matplotlib.backends.backend_qt5agg",
    "matplotlib.backends.backend_qtagg",
    "PyQt5.sip",
]

a = Analysis(
    ["PingerApp/PingerApp.py"],
    pathex=[],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={"matplotlib": {"backends": ["Qt5Agg"]}},
    runtime_hooks=[],
    excludes=["tkinter"],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)
pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="PingerApp",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name="PingerApp",
)
