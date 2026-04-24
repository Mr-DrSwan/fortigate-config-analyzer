# FortiGate Analyzer — Архитектура

> Актуально после рефакторинга апрель 2026.

---

## Структура проекта

```
FortiGate_Analyzer/
│
├── app.py                   # GUI (Tkinter) + CLI точка входа
├── fortigate_analyzer.py    # Ядро парсера: FortigateConfigParser
├── address_utils.py         # Утилиты IP/подсетей (чистые функции)
├── config_sections.py       # Замена/добавление секций в .conf
├── security_utils.py        # Path traversal, SHA256, Excel-санитизация
├── perf_metrics.py          # PerfRecorder — JSONL-лог производительности
│
├── services/
│   ├── device_vault.py      # DeviceRecord, загрузка устройств с диска
│   └── updater.py           # Версионирование, GitHub API, обновления
│
├── tests/
│   ├── conftest.py          # Общие pytest fixtures
│   ├── test_parser.py
│   ├── test_parser_negative.py
│   ├── test_address_utils.py
│   ├── test_config_sections.py
│   ├── test_security_utils.py
│   ├── test_perf_metrics.py
│   ├── test_update_versioning.py
│   └── test_app_interface_and_functions.py
│
├── assets/                  # Иконки (.icns, .ico, .png)
├── installer/               # Inno Setup скрипт (Windows)
├── requirements.txt
└── VERSION
```

---

## Модули

### `fortigate_analyzer.py`

**Класс:** `FortigateConfigParser(config_file: str)`

Читает `.conf`-файл FortiGate, строит индекс секций и извлекает `edit/next`-блоки в словари.

| Метод | Секция конфига | Лист Excel |
|---|---|---|
| `parse_local_users()` | `user local` | `Локальные_пользователи` |
| `parse_user_groups()` | `user group` | `Группы_пользователей` |
| `parse_firewall_rules()` | `firewall policy` | `Firewall_правила` |
| `parse_ipsec_tunnels()` | `vpn ipsec phase1-interface` | `IPSec_Туннели` |
| `parse_static_routes()` | `router static` | `Статические_маршруты` |
| `parse_nat_rules()` | `firewall vip` | `NAT_правила` |
| `parse_addresses()` | `firewall address` + `addrgrp` | `Адреса` + `Группы_адресов` |
| `parse_vpn_users()` | `user peer` + `user group` | `VPN_Пользователи` |
| `parse_all()` | все выше | все листы |

**Детали:**
- `_parse_set_value(raw)` — единственный метод разбора `set`-значений, корректно обрабатывает многократные кавычки FortiGate.
- `_read_config()` бросает `FileNotFoundError`/`OSError`, не делает `sys.exit()`.
- `find_duplicate_addresses()` / `build_transfer_plan()` / `render_*_config_lines()` — функциональность переноса адресов между устройствами.
- `save_to_excel()` — экранирует ячейки `=`,`+`,`-`,`@` (formula injection protection).

---

### `app.py`

**Запуск:**
- `python3 app.py` — GUI
- `python3 app.py --input path.conf --output result.xlsx` — CLI без GUI

**Класс `App(root: tk.Tk)`** — основной UI (~4300 строк). Tkinter, тёмная тема в стиле Termius, нативные системные скроллбары.

**Состояние:**
- `self.devices` — загруженные устройства (`Dict[str, DeviceRecord]`)
- `self.selected_device_name` — выбранное устройство
- `self.last_parser` — последний загруженный парсер

**Зависимости:**
```
app.py
  ├── fortigate_analyzer.FortigateConfigParser
  ├── address_utils.*
  ├── config_sections.replace_or_append_config_section
  ├── security_utils.ensure_under_root, sanitize_spreadsheet_text
  ├── perf_metrics.PerfRecorder
  ├── services.device_vault.DeviceRecord, get_app_data_dir, load_devices_from_disk
  └── services.updater.fetch_remote_version, get_platform_asset_name, ...
```

---

### `services/device_vault.py`

`DeviceRecord` (dataclass) — данные одного устройства: имя, папка, пути к `.conf`/`.xlsx`/`.csv`, время последнего обновления.

`load_devices_from_disk(devices_dir)` — сканирует директорию, защита от path traversal через `ensure_under_root`.

`get_app_data_dir()` — платформо-зависимая директория данных:
- macOS: `~/Library/Application Support/FortiGateAnalyzer`
- Windows: `%APPDATA%/FortiGateAnalyzer`

---

### `services/updater.py`

Версионирование и скачивание обновлений. Нет зависимостей на Tkinter.

- `parse_version(v)` / `is_newer_version(remote, local)` — сравнение версий
- `fetch_remote_version(owner, repo)` — читает `VERSION` с GitHub
- `download_update_asset(url, filename, expected_sha256)` — скачивает и проверяет SHA256
- `run_installer(path, on_quit)` — запускает установщик

---

### `address_utils.py`

Чистые функции без состояния.

| Функция | Описание |
|---|---|
| `extract_first_ipv4(value)` | IPv4 → int (для сортировки) |
| `subnet_to_display(subnet)` | `"10.0.0.0 255.255.255.0"` → `"10.0.0.0/24"` |
| `normalize_subnet_value(raw)` | CIDR или `ip mask`, бросает `ValueError` |
| `normalize_iprange_value(raw)` | `ip1-ip2` или `ip1 ip2`, бросает `ValueError` |
| `get_address_display_value(objects, name)` | FQDN / диапазон / CIDR / type |
| `address_sort_key(objects, name)` | Ключ сортировки по IP → FQDN → имя |
| `address_sort_mode_key(objects, name, mode)` | То же с учётом режима |

---

### `config_sections.py`

`replace_or_append_config_section(config_text, section_name, body)` — находит `config <section> ... end` и заменяет тело. Если блока нет — добавляет в конец.

---

### `security_utils.py`

- `ensure_under_root(path, root)` — защита от path traversal
- `sanitize_spreadsheet_text(value)` — экранирует `=`, `+`, `-`, `@`, `\t`, `\r`
- `sha256_file(path)` / `parse_sha256_file(content, filename)` — верификация скачанных обновлений

---

### `perf_metrics.py`

`PerfRecorder(target_file)` — пишет JSONL-лог производительности, создаёт директории автоматически.

```python
recorder.record("parse_all", elapsed_ms=412.5, {"rows": 1200})
# → {"ts": 1714000000.0, "metric": "parse_all", "elapsed_ms": 412.5, "rows": 1200}
```

---

## Тесты

```bash
python3 -m pytest tests/ -q
```

**Текущий результат:** все тесты зелёные (апрель 2026).

| Тест-файл | Что покрыто |
|---|---|
| `test_parser.py` | Блоки, политики, адреса, transfer plan, render |
| `test_parser_negative.py` | Несуществующий файл, пустой конфиг, незакрытые блоки |
| `test_address_utils.py` | Все функции, позитив + негатив |
| `test_config_sections.py` | Замена и добавление секции |
| `test_security_utils.py` | Path traversal, SHA256, санитизация |
| `test_perf_metrics.py` | Создание файла, JSON, append |
| `test_update_versioning.py` | `parse_version`, `is_newer_version` |
| `test_app_interface_and_functions.py` | Инициализация App, CLI, `analyze_config`, утилиты |

Общие fixtures живут в `tests/conftest.py` (`make_parser`, `full_config_path`, `full_parser`).

---

## Потоки данных

### Анализ конфига

```
.conf файл → FortigateConfigParser
    ├── _read_config()
    ├── _build_section_ranges()
    └── parse_all()
            ├── parse_firewall_rules()   ← firewall_translations
            ├── parse_addresses()        ← address_objects, address_group_*
            └── ...
    ↓
parser.dataframes → save_to_excel() → .xlsx
```

### Перенос адресов

```
parse_addresses() → address_objects, address_group_members
    ↓
build_transfer_plan(selected, existing_index, color_overrides)
    ↓
Dict: addresses_to_create, groups_to_create, duplicate_*, commands_text
```

---

## Известный техдолг

| Проблема | Файл | Приоритет |
|---|---|---|
| `App` ~4300 строк, UI и бизнес-логика смешаны | `app.py` | Средний |
| `build_transfer_plan` возвращает `Dict[str, object]` без строгой типизации | `fortigate_analyzer.py` | Низкий |
| `errors='ignore'` при чтении — тихая потеря символов при нестандартной кодировке | `fortigate_analyzer.py` | Низкий |
