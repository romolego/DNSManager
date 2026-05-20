#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""DNS Manager — Windows-приложение для управления DNS.

Это тонкая точка входа. Вся логика вынесена в пакет ``dnsmgr`` (см.
``dnsmgr/__init__.py`` для карты модулей). Файл намеренно остаётся под
именем ``dns_manager.py`` и собирается PyInstaller'ом в ``DNSManager.exe`` —
на это имя ссылаются записи автозапуска в реестре и Планировщике заданий,
поэтому переименовывать его нельзя без миграции этих ссылок.

Запуск:
    python dns_manager.py              # обычный запуск, окно видно
    python dns_manager.py --minimized  # запуск в трей (используется автозапуском)
"""

import os
import sys

# При обычном запуске Python уже добавляет директорию скрипта в sys.path,
# и `import dnsmgr` находится. При сборке PyInstaller'ом пакет включается
# в бандл по анализу импортов. На всякий случай гарантируем, что каталог
# рядом со скриптом есть в путях поиска модулей.
_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

from dnsmgr.main import main

if __name__ == "__main__":
    main()
