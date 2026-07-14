# -*- mode: python ; coding: utf-8 -*-
from PyInstaller.utils.hooks import collect_submodules, collect_data_files

hiddenimports = [
    # scapy
    'scapy.layers.inet', 'scapy.layers.l2', 'scapy.layers.inet6',
    'scapy.packet', 'scapy.sendrecv', 'scapy.arch.windows',
    'scapy.config', 'scapy.route', 'scapy.interfaces',
    # pystray
    'pystray._win32',
    # Pillow
    'PIL._imaging', 'PIL.Image', 'PIL.ImageDraw',
    # cryptography
    'cryptography.hazmat.backends.openssl',
    # psutil
    'psutil._psutil_windows',
    # mitmproxy (heavy, but needed for MITM mode)
    'mitmproxy.options', 'mitmproxy.proxy.server', 'mitmproxy.tools.dump',
    'mitmproxy.addons', 'mitmproxy.master',
]

datas = [
    ('ui/dashboard.html', 'ui'),
]

a = Analysis(
    ['cli/main.py'],
    pathex=[],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='agentmon',
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
    icon=None,
)
