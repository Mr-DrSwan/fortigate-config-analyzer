# FortiGate Config Analyzer

![Forti meme cover](assets/cover-meme.png)

Это приложение разбирает конфиг FortiGate (`.conf`) и делает понятный `Excel (.xlsx)` отчет.

Нужно быстро посмотреть, что настроено в фаерволе? Это как раз для этого.

Что попадает в отчет:

- локальные пользователи и группы;
- правила фаервола (включая много дополнительных полей);
- IPSec туннели;
- статические маршруты;
- NAT (VIP / port-forward);
- адреса и группы адресов;
- VPN пользователи.

## Скачать готовые сборки

- Windows (`.exe`): https://github.com/Mr-DrSwan/fortigate-config-analyzer/releases/latest/download/FortiGateAnalyzer.exe
- Windows Installer (`Setup.exe`): https://github.com/Mr-DrSwan/fortigate-config-analyzer/releases/latest/download/FortiGateAnalyzer-Setup.exe
- macOS (`.app` в zip): https://github.com/Mr-DrSwan/fortigate-config-analyzer/releases/latest/download/FortiGateAnalyzer-macOS.zip

## Быстрый старт (Python)

1. Открой терминал в папке проекта:
   - `cd FortiGate_Analyzer`
2. Установи зависимости:
   - `python3 -m pip install -r requirements.txt`
3. Запусти GUI:
   - `python3 app.py`

## CLI режим

- `python3 app.py --input "/path/to/fortigate.conf" --output "/path/to/result.xlsx"`

## Локальная сборка

### Windows

1. `python -m pip install -r requirements.txt`
2. `pyinstaller --noconfirm --onefile --windowed --icon assets/forti-analyzer-icon.ico --name FortiGateAnalyzer app.py`
3. Готовый файл:
   - `dist/FortiGateAnalyzer.exe`
4. Установщик (Inno Setup):
   - установи Inno Setup 6
   - запусти `build_installer.bat`
   - получишь `dist/FortiGateAnalyzer-Setup.exe`

### macOS

1. `python3 -m pip install -r requirements.txt`
2. `pyinstaller --noconfirm --windowed --icon assets/forti-analyzer-icon.icns --name FortiGateAnalyzer app.py`
3. Готовый файл:
   - `dist/FortiGateAnalyzer.app`

## Тесты (ветка dev)

Добавлены автотесты `pytest` в `tests/test_parser.py`:

- проверка парсинга `edit/set` блоков из конфигурации;
- проверка формирования и перевода колонок для firewall правил;
- smoke-проверка структуры выходного `DataFrame`.

Запуск локально:

- `python3 -m pip install -r requirements.txt`
- `python3 -m pip install pytest`
- `pytest -q`

## CI/CD

В проекте настроены workflow:

- `.github/workflows/ci.yml` — тесты на `push/pull_request` для `dev`, `main`, `master`;
- `.github/workflows/build-windows-exe.yml` — сборка Windows;
- `.github/workflows/build-macos-app.yml` — сборка macOS;
- `.github/workflows/cd-release.yml` — автопубликация релиза при теге `v*`.

### Как работаем по веткам

- все изменения вносим в `dev`;
- `main` оставляем под стабильные релизы.
