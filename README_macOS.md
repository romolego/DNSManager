# DNS Manager — версия для macOS

Это ветка `macos`: тот же код, что и Windows-версия, с платформенным
бэкендом для macOS. **Ключевые функции** — подключение к GeoHide DNS и
сброс к стандартному (DHCP) DNS — работают так же, как на Windows.

## Что работает на macOS

| Функция | Реализация на macOS |
|---|---|
| Список сетевых сервисов («адаптеров») | `networksetup -listallnetworkservices` |
| Активный интерфейс (через что идёт интернет) | `route -n get default` |
| Чтение текущего DNS | `networksetup -getdnsservers` |
| **Подключение DNS (GeoHide и др.)** | `networksetup -setdnsservers` |
| **Сброс к стандартному DNS** | `networksetup -setdnsservers <сервис> Empty` |
| Сброс DNS-кеша | `dscacheutil -flushcache` + `killall -HUP mDNSResponder` |
| Резолв `dns.geohide.ru`, получение DNS по ссылке | как на Windows (кроссплатформенно) |
| Данные приложения (настройки, лог) | `~/Library/Application Support/DNSManager/` |

### Права администратора
Изменение DNS в macOS требует прав root. Приложение **не** запускается под
root целиком — вместо этого каждое изменение DNS повышается отдельно через
нативный системный диалог пароля macOS (`osascript … with administrator
privileges`). То есть: нажал «GeoHide» → один раз ввёл пароль → DNS применён.

## Чего на macOS пока нет (второстепенное)
- **Системный трей** отключён (на macOS он конфликтует с tkinter). Закрытие
  окна завершает приложение.
- **Фоновый мониторинг / автовосстановление DNS** отключён, чтобы не
  всплывал запрос пароля в неожиданные моменты. Подключение и сброс —
  полностью ручные и работают.
- **Автозапуск «с правами администратора»** (аналог Планировщика заданий)
  не реализован; обычный автозапуск делается через LaunchAgent по галочке.

---

## Вариант A. Быстрый тест из исходников (без сборки)
Самый быстрый способ проверить на Mac. Нужен Python с Tk (подойдёт установщик
с [python.org](https://www.python.org/downloads/macos/) — он включает Tcl/Tk).

```bash
cd DNSManager
python3 -m pip install Pillow
python3 dns_manager.py
```

## Вариант B. Собрать .app на Mac
```bash
cd DNSManager
chmod +x build_macos.sh
./build_macos.sh
open dist/DNSManager.app
```
Готовый бандл: `dist/DNSManager.app` — его можно скопировать в `/Applications`.

> Сборка идёт под архитектуру машины: на Apple Silicon → arm64, на Intel →
> x86_64. Собранный .app запустится на той же архитектуре (или на arm64
> через Rosetta).

## Вариант C. Собрать .app в облаке (если Mac под рукой нет)
В репозитории есть workflow `.github/workflows/build-macos.yml`. После
`git push origin macos` GitHub Actions соберёт `DNSManager.app` на macOS-раннере.
Скачать: вкладка **Actions** → последний запуск **Build macOS app** →
артефакт **DNSManager-macos-…**. Внутри zip — готовый `DNSManager.app`.

Выбрать архитектуру можно вручную: Actions → Build macOS app → **Run workflow**
→ `macos-14` (Apple Silicon) или `macos-13` (Intel).

---

## Первый запуск: предупреждение Gatekeeper
Приложение **не подписано** Apple Developer ID. На чужом Mac macOS при первом
открытии может сказать, что разработчик не проверен. Открыть:

- **правый клик** по `DNSManager.app` → **«Открыть»** → **«Открыть»**; или
- в Терминале снять «карантин»:
  ```bash
  xattr -dr com.apple.quarantine /путь/к/DNSManager.app
  ```

(Для распространения без этого шага нужен платный Apple Developer ID и
нотаризация — это отдельная история, в задачу не входит.)
