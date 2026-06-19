#!/usr/bin/env bash
# Сборка DNS Manager в macOS-приложение (.app).
# Запускать НА macOS (PyInstaller не умеет кросс-компиляцию с Windows).
#
#   chmod +x build_macos.sh
#   ./build_macos.sh
#
# Результат: dist/DNSManager.app
set -euo pipefail
cd "$(dirname "$0")"

PYTHON="${PYTHON:-python3}"

echo "==> Python: $("$PYTHON" --version)"

# Изолированное окружение сборки
"$PYTHON" -m venv .venv-macos
# shellcheck disable=SC1091
source .venv-macos/bin/activate

python -m pip install --upgrade pip
python -m pip install -r requirements-macos.txt

# Чистая сборка по spec
pyinstaller --noconfirm --clean DNSManager_macos.spec

# Снять карантин, чтобы локально открывалось без правого клика → «Открыть»
xattr -dr com.apple.quarantine dist/DNSManager.app 2>/dev/null || true

echo ""
echo "==> Готово: dist/DNSManager.app"
echo "    Запуск: open dist/DNSManager.app"
echo ""
echo "    Приложение НЕ подписано Apple Developer ID. На ДРУГОМ Mac при первом"
echo "    запуске macOS может показать предупреждение Gatekeeper. Открыть так:"
echo "    правый клик по DNSManager.app → «Открыть» → «Открыть»;"
echo "    либо в Терминале:  xattr -dr com.apple.quarantine /путь/к/DNSManager.app"
