#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DIST_DIR="${ROOT_DIR}/dist"
BUILD_ROOT="${DIST_DIR}/deb_build"

if ! command -v dpkg-deb >/dev/null 2>&1; then
  echo "Error: dpkg-deb is required but not installed."
  exit 1
fi

VERSION="$(python3 - <<'PY'
from pathlib import Path
content = Path("pyproject.toml").read_text(encoding="utf-8")
version = None
for line in content.splitlines():
    stripped = line.strip()
    if stripped.startswith("version") and "=" in stripped:
        version = stripped.split("=", 1)[1].strip().strip('"').strip("'")
        break
if not version:
    raise SystemExit("Unable to find project version in pyproject.toml")
print(version)
PY
)"

PKG_NAME="kittysploit"
PKG_ARCH="all"
PKG_DIR_NAME="${PKG_NAME}_${VERSION}_${PKG_ARCH}"
PKG_ROOT="${BUILD_ROOT}/${PKG_DIR_NAME}"
DEBIAN_DIR="${PKG_ROOT}/DEBIAN"
OPT_DIR="${PKG_ROOT}/opt/${PKG_NAME}"
BIN_DIR="${PKG_ROOT}/usr/local/bin"
OUTPUT_DEB="${DIST_DIR}/${PKG_DIR_NAME}.deb"

rm -rf "${PKG_ROOT}"
mkdir -p "${DEBIAN_DIR}" "${OPT_DIR}" "${BIN_DIR}" "${DIST_DIR}"

python3 - "${ROOT_DIR}" "${OPT_DIR}" <<'PY'
import os
import shutil
import sys
from pathlib import Path

root = Path(sys.argv[1]).resolve()
dst = Path(sys.argv[2]).resolve()

ignore_names = {
    ".git",
    ".github",
    ".idea",
    ".vscode",
    ".pytest_cache",
    ".mypy_cache",
    "__pycache__",
    "dist",
    "build",
    "venv",
    ".venv",
}

def should_skip(path: Path) -> bool:
    if any(part in ignore_names for part in path.parts):
        return True
    name = path.name
    if name.endswith((".pyc", ".pyo", ".pyd", ".deb")):
        return True
    return False

for entry in root.iterdir():
    if entry.name == "dist":
        continue
    if should_skip(entry):
        continue

    target = dst / entry.name
    if entry.is_dir():
        shutil.copytree(
            entry,
            target,
            dirs_exist_ok=True,
            ignore=shutil.ignore_patterns(
                "__pycache__", "*.pyc", "*.pyo", "*.pyd", ".git", ".pytest_cache",
                ".mypy_cache", "venv", ".venv", "*.deb"
            ),
        )
    else:
        shutil.copy2(entry, target)
PY

python3 - "${OPT_DIR}" <<'PY'
import os
import shutil
import sys
from pathlib import Path

opt = Path(sys.argv[1]).resolve()
sys.path.insert(0, str(opt))
os.chdir(opt)

from core.registry.client import ExtensionClient
from core.registry.manifest import ManifestParser

OFFICIAL_APPS = ("kittyproxy", "kittyosint", "kittyprotocol")
client = ExtensionClient(extensions_dir=str(opt / "extensions"))

for app_id in OFFICIAL_APPS:
    app_src = opt / "apps" / app_id
    if not app_src.is_dir():
        raise SystemExit(f"apps/{app_id} missing")

    target = opt / "extensions" / app_id / app_id / "latest"
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.exists():
        shutil.rmtree(target)
    shutil.copytree(app_src, target)

    manifest = ManifestParser.parse(str(target / "extension.toml"))
    if not manifest:
        raise SystemExit(f"Invalid extension.toml for {app_id}")

    if not client._create_stub_files(manifest, str(target), "latest", marketplace_id=app_id):
        raise SystemExit(f"Failed to create launcher for {app_id}")

    print(f"Bundled extension {app_id} -> {target}")
PY

cat > "${DEBIAN_DIR}/control" <<EOF
Package: ${PKG_NAME}
Version: ${VERSION}
Section: utils
Priority: optional
Architecture: ${PKG_ARCH}
Maintainer: KittySploit Team <support@kittysploit.com>
Depends: python3, python3-venv, python3-pip
Description: KittySploit modular penetration testing framework
 KittySploit provides a modular penetration testing framework with
 CLI and auxiliary interfaces.
EOF

cat > "${DEBIAN_DIR}/postinst" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

APP_DIR="/opt/kittysploit"
if [ ! -d "${APP_DIR}" ]; then
  echo "Error: ${APP_DIR} not found."
  exit 1
fi

cd "${APP_DIR}"

if [ ! -d "venv" ]; then
  python3 -m venv venv
fi

./venv/bin/pip install --upgrade pip
./venv/bin/pip install -r install/requirements.txt

chmod +x "${APP_DIR}/start_kittysploit.sh" || true
chmod +x "${APP_DIR}/agent.py" || true
EOF

cat > "${DEBIAN_DIR}/prerm" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
exit 0
EOF

cat > "${BIN_DIR}/kittysploit" <<'EOF'
#!/usr/bin/env bash
export KITTYSPLOIT_DB_PATH="${XDG_DATA_HOME:-$HOME/.local/share}/kittysploit/database/database.db"
exec /opt/kittysploit/start_kittysploit.sh "$@"
EOF

cat > "${BIN_DIR}/kittymcp" <<'EOF'
#!/usr/bin/env bash
export KITTYSPLOIT_DB_PATH="${XDG_DATA_HOME:-$HOME/.local/share}/kittysploit/database/database.db"
exec /opt/kittysploit/venv/bin/python /opt/kittysploit/kittymcp.py "$@"
EOF

cat > "${BIN_DIR}/kittyproxy" <<'EOF'
#!/usr/bin/env bash
export KITTYSPLOIT_DB_PATH="${XDG_DATA_HOME:-$HOME/.local/share}/kittysploit/database/database.db"
exec /opt/kittysploit/venv/bin/python /opt/kittysploit/launch_kittyproxy.py "$@"
EOF

cat > "${BIN_DIR}/kittyosint" <<'EOF'
#!/usr/bin/env bash
export KITTYSPLOIT_DB_PATH="${XDG_DATA_HOME:-$HOME/.local/share}/kittysploit/database/database.db"
exec /opt/kittysploit/venv/bin/python /opt/kittysploit/launch_kittyosint.py "$@"
EOF

cat > "${BIN_DIR}/kittyprotocol" <<'EOF'
#!/usr/bin/env bash
export KITTYSPLOIT_DB_PATH="${XDG_DATA_HOME:-$HOME/.local/share}/kittysploit/database/database.db"
exec /opt/kittysploit/venv/bin/python /opt/kittysploit/launch_kittyprotocol.py "$@"
EOF

chmod 755 "${DEBIAN_DIR}/postinst" "${DEBIAN_DIR}/prerm"
chmod 755 "${BIN_DIR}/kittysploit" "${BIN_DIR}/kittymcp" "${BIN_DIR}/kittyproxy" "${BIN_DIR}/kittyosint" "${BIN_DIR}/kittyprotocol"

DPKG_HELP="$(dpkg-deb --help || true)"
if [[ "${DPKG_HELP}" == *"--root-owner-group"* ]]; then
  dpkg-deb --build --root-owner-group "${PKG_ROOT}" "${OUTPUT_DEB}"
else
  dpkg-deb --build "${PKG_ROOT}" "${OUTPUT_DEB}"
fi

echo "Debian package created:"
echo "  ${OUTPUT_DEB}"
