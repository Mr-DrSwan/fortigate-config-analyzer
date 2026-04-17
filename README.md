# FortiGate Config Analyzer

![Forti meme cover](assets/cover-meme.png)

GUI/CLI приложение для анализа конфигурации FortiGate (`.conf`) и экспорта результата в `Excel (.xlsx)`.

## Что анализирует

- локальные пользователи и группы;
- правила фаервола (со всеми доступными полями);
- IPSec туннели;
- статические маршруты;
- NAT (VIP/port-forward);
- адреса и группы адресов;
- VPN пользователи.

## Скачать готовые сборки

- Windows (`.exe`): https://github.com/Mr-DrSwan/fortigate-config-analyzer/releases/latest/download/FortiGateAnalyzer.exe
- macOS (`.app` в zip): https://github.com/Mr-DrSwan/fortigate-config-analyzer/releases/latest/download/FortiGateAnalyzer-macOS.zip

## Запуск как Python приложение

1. Открой терминал в папке проекта:
   - `cd FortiGate_Analyzer`
2. Установи зависимости:
   - `python3 -m pip install -r requirements.txt`
3. Запусти GUI:
   - `python3 app.py`

## CLI режим

- `python3 app.py --input "/path/to/fortigate.conf" --output "/path/to/result.xlsx"`

## Локальная сборка Windows

1. `python -m pip install -r requirements.txt`
2. `pyinstaller --noconfirm --onefile --windowed --icon assets/forti-analyzer-icon.ico --name FortiGateAnalyzer app.py`
3. Готовый файл:
   - `dist/FortiGateAnalyzer.exe`

## Локальная сборка macOS

1. `python3 -m pip install -r requirements.txt`
2. `pyinstaller --noconfirm --windowed --icon assets/forti-analyzer-icon.icns --name FortiGateAnalyzer app.py`
3. Готовый файл:
   - `dist/FortiGateAnalyzer.app`

## CI сборки (GitHub Actions)

В проекте настроены workflow:

- `.github/workflows/build-windows-exe.yml`
- `.github/workflows/build-macos-app.yml`
