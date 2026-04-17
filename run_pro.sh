#!/bin/bash

# FortiGate Analyzer - Скрипт запуска для Mac/Linux

# Проверяем наличие виртуального окружения
if [ -d ".venv" ]; then
    echo "Активация виртуального окружения..."
    source .venv/bin/activate
    python app.py "$@"
else
    echo "Виртуальное окружение не найдено."
    echo "Сначала выполните: python install.py"
    exit 1
fi