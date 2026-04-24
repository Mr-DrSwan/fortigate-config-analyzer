# FortiGate Config Analyzer

[![CI](https://github.com/Mr-DrSwan/fortigate-config-analyzer/actions/workflows/ci.yml/badge.svg?branch=dev)](https://github.com/Mr-DrSwan/fortigate-config-analyzer/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/Mr-DrSwan/fortigate-config-analyzer/branch/main/graph/badge.svg)](https://codecov.io/gh/Mr-DrSwan/fortigate-config-analyzer)

![Forti meme cover](assets/cover-meme.png)

Разбирает конфиг FortiGate (`.conf`) и генерирует читаемый Excel-отчёт.

**Что попадает в отчёт:**
- локальные пользователи и группы
- правила фаервола (с расширенными полями)
- IPSec туннели
- статические маршруты
- NAT (VIP / port-forward)
- адреса и группы адресов
- VPN пользователи

## Скачать готовую версию

- Windows: [FortiGateAnalyzer-Setup.exe](https://github.com/Mr-DrSwan/fortigate-config-analyzer/releases/latest/download/FortiGateAnalyzer-Setup.exe)
- macOS: [FortiGateAnalyzer-macOS.pkg](https://github.com/Mr-DrSwan/fortigate-config-analyzer/releases/latest/download/FortiGateAnalyzer-macOS.pkg)

## Быстрый старт

```bash
pip install -r requirements.txt
python3 app.py
```

**CLI:**
```bash
python3 app.py --input /path/to/fortigate.conf --output result.xlsx
```

## Локальная сборка

### macOS

```bash
pip install -r requirements.txt
python3 -m PyInstaller --noconfirm FortiGateAnalyzer.spec --distpath local_build
# → local_build/FortiGateAnalyzer.app
```

### Windows

```bash
pip install -r requirements.txt
python -m PyInstaller --noconfirm --onefile --windowed --icon assets/forti-analyzer-icon.ico --name FortiGateAnalyzer app.py
# → dist/FortiGateAnalyzer.exe
# Установщик: build_installer.bat (требует Inno Setup 6)
```

## Тесты

```bash
pip install pytest
pytest -q
```

Покрыто: парсер, утилиты адресов, конфиг-секции, безопасность, метрики производительности, GUI smoke-тест.

## CI/CD

- `ci.yml` — тесты при push/PR в `dev`, `main`
- `build-windows-exe.yml` / `build-macos-app.yml` — сборка артефактов
- `cd-release.yml` — публикация релиза при теге `v*`

## Ветки

- `dev` — текущая разработка
- `main` — стабильные релизы
