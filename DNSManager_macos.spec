# -*- mode: python ; coding: utf-8 -*-
# PyInstaller-спецификация для macOS-сборки DNS Manager (.app-бандл).
#
# Отличия от Windows-спека (DNSManager.spec):
#   - собирается .app через BUNDLE (а не одиночный .exe);
#   - console=False (оконное приложение);
#   - нет version.txt (это Windows-ресурс версии);
#   - pystray исключён — на macOS трей отключён, а его бэкенд тянет pyobjc.
#
# Сборка (на macOS):  pyinstaller --noconfirm --clean DNSManager_macos.spec
from PyInstaller.utils.hooks import collect_submodules

hiddenimports = ['dnsmgr']
hiddenimports += collect_submodules('dnsmgr')

a = Analysis(
    ['dns_manager.py'],
    pathex=[],
    binaries=[],
    datas=[],
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=['pystray'],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name='DNSManager',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
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
    a.datas,
    strip=False,
    upx=False,
    upx_exclude=[],
    name='DNSManager',
)

app = BUNDLE(
    coll,
    name='DNSManager.app',
    icon=None,
    bundle_identifier='com.dnsmanager.app',
    info_plist={
        'CFBundleName': 'DNS Manager',
        'CFBundleDisplayName': 'DNS Manager',
        'CFBundleShortVersionString': '1.0.0',
        'CFBundleVersion': '1.0.0',
        'NSHighResolutionCapable': True,
        # Обычное оконное приложение (не агент в menubar)
        'LSUIElement': False,
        'LSMinimumSystemVersion': '11.0',
    },
)
