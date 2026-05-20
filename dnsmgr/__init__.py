"""DNS Manager — Windows-приложение для управления DNS.

Пакет разбит на модули с однонаправленным графом зависимостей:

    constants → logger → config → process → network → geohide → monitor → app → main
                                          autostart ──┘

Точка входа — корневой `dns_manager.py` (он же — имя исполняемого exe и
ярлыков в реестре/Планировщике), который импортирует `main` отсюда.
"""

from dnsmgr.constants import APP_NAME, APP_VERSION

__all__ = ["APP_NAME", "APP_VERSION"]
