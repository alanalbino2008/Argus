# PyInstaller recipe for the Argus desktop app (Argus Personal with Python and everything bundled).
#
#   pyinstaller packaging/desktop/argus.spec --noconfirm --distpath dist --workpath build/pyinstaller
#
# Expects, when present: build/icons (make_icons.py), build/argus-desktop.json (write_config.py)
# and build/browser (fetch_browser.py). Produces dist/Argus/ (and dist/Argus.app on macOS).
# ruff: noqa
import sys
from pathlib import Path

from PyInstaller.utils.hooks import collect_data_files, collect_submodules

ROOT = Path(SPECPATH).resolve().parent.parent
BUILD = ROOT / "build"
ICONS = BUILD / "icons"
sys.path.insert(0, str(ROOT))
from argus import __version__  # noqa: E402

datas = [
    (str(ROOT / "argus" / "web"), "argus/web"),
    (str(ROOT / "argus" / "data"), "argus/data"),
    (str(ROOT / "argus" / "storage" / "migrations"), "argus/storage/migrations"),  # Alembic reads these files
]
for package in ("phonenumbers", "tzdata", "reportlab", "stix2", "certifi", "anthropic"):
    datas += collect_data_files(package)
if (BUILD / "argus-desktop.json").is_file():
    datas.append((str(BUILD / "argus-desktop.json"), "."))
if (BUILD / "browser").is_dir():
    datas.append((str(BUILD / "browser"), "browser"))

hiddenimports = (
    # every Argus module, found from the files (argus.api, argus.core and argus.cli have no __init__.py,
    # which collect_submodules would skip); modules are looked up by name at run time
    [
        ".".join(path.relative_to(ROOT).with_suffix("").parts).removesuffix(".__init__")
        for path in sorted((ROOT / "argus").rglob("*.py"))
        if "migrations" not in path.parts
    ]
    + collect_submodules("uvicorn")
    + collect_submodules("phonenumbers")
    + collect_submodules("stix2")
    + ["aiosqlite", "sqlalchemy.dialects.sqlite.aiosqlite", "alembic.runtime.migration", "alembic.ddl.sqlite"]
)
hiddenimports = [m for m in hiddenimports if ".tests" not in m]

a = Analysis(
    [str(Path(SPECPATH) / "argus_app.py")],
    pathex=[str(ROOT)],
    datas=datas,
    hiddenimports=hiddenimports,
    excludes=["tkinter", "pytest", "IPython", "matplotlib", "numpy", "pandas", "asyncpg"],
    noarchive=False,
)
pyz = PYZ(a.pure)
icon = str(ICONS / ("argus.ico" if sys.platform == "win32" else "argus.icns")) if ICONS.is_dir() else None
exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="Argus",
    console=sys.platform.startswith("linux"),  # Windows and macOS: no terminal window
    icon=icon,
    version=None,
)
coll = COLLECT(exe, a.binaries, a.datas, strip=False, upx=False, name="Argus")

if sys.platform == "darwin":
    app = BUNDLE(
        coll,
        name="Argus.app",
        icon=icon,
        bundle_identifier="app.argus.personal",
        version=__version__,
        info_plist={
            "CFBundleDisplayName": "Argus",
            "CFBundleShortVersionString": __version__,
            "NSHighResolutionCapable": True,
            "LSMinimumSystemVersion": "11.0",
        },
    )
