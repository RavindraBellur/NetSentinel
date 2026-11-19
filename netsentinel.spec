# PyInstaller spec for Prahari - build the Windows exe with ONE command:
#
#     pip install pyinstaller
#     pyinstaller netsentinel.spec
#
# Result: dist\Prahari.exe (single file, Python bundled, nothing to install).
# Every module and data file is listed here, so no --hidden-import flags are needed.

block_cipher = None

from PyInstaller.utils.hooks import collect_submodules

HIDDEN = [
    "netscan.agent", "netscan.anomaly", "netscan.posture", "netscan.push", "netscan.backup",
    "netscan.telegram", "netscan.upgrade", "netscan.snmpv3", "netscan.wifi", "netscan.topology",
    "netscan.sla", "netscan.pdf", "netscan.ports", "netscan.remediation",
    "netscan.vault", "netscan.defaults", "netscan.scheduled", "netscan.sensors", "netscan.mirror", "netscan.alerts", "netscan.apitokens", "netscan.auth",
    "netscan.certs", "netscan.diagnose", "netscan.discovery", "netscan.fingerprint",
    "netscan.fleet", "netscan.heartbeat", "netscan.monitor", "netscan.netflow",
    "netscan.netguard", "netscan.netinfo", "netscan.oidc", "netscan.oui",
    "netscan.poll", "netscan.remote", "netscan.report", "netscan.scanner",
    "netscan.settings", "netscan.sites", "netscan.snmp", "netscan.store",
    "netscan.syslogrx", "netscan.tailnet", "netscan.tlsutil", "netscan.totp",
    "netscan.updater", "netscan.wan", "netscan.webui",
    # optional extras: harmless when missing, bundled when present
    "psutil", "anthropic", "cryptography", "sqlite3", "ssl", "email.mime.text",
]

a = Analysis(
    ["netsentinel.py"],
    pathex=[],
    binaries=[],
    datas=[("netscan", "netscan"), ("netscan/static", "netscan/static"), ("README.md", "."), ("EULA.txt", "."), ("LIMITS.md", "."), ("sbom.json", ".")],
    hiddenimports=HIDDEN + collect_submodules("anthropic"),
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=["tkinter", "matplotlib", "numpy", "PIL", "scapy"],  # scapy is GPL: never bundled
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
    name="Prahari",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon="netsentinel.ico",
)
