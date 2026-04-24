#!/usr/bin/env python3
"""
Скрипт для установки зависимостей FortiGate Analyzer
Запустите: python install.py
"""

import sys
import subprocess
import os
import platform


def print_header():
    print("=" * 70)
    print("FortiGate Configuration Analyzer - Установка зависимостей")
    print("=" * 70)


def check_python_version():
    """Проверка версии Python"""
    print("\n1. Проверка версии Python...")
    version = sys.version_info
    if version.major < 3 or (version.major == 3 and version.minor < 8):
        print(f"✗ Требуется Python 3.8+, у вас {version.major}.{version.minor}.{version.micro}")
        print("Скачайте Python с https://python.org")
        return False
    print(f"✓ Python {version.major}.{version.minor}.{version.micro} - OK")
    return True


def check_and_create_venv():
    """Проверка и создание виртуального окружения"""
    print("\n2. Настройка виртуального окружения...")

    # Проверяем, есть ли уже venv
    venv_dir = '.venv'
    if os.path.exists(venv_dir):
        print(f"✓ Виртуальное окружение уже существует в {venv_dir}")
        return True

    # Создаем venv
    print("Создание виртуального окружения...")
    try:
        subprocess.check_call([sys.executable, "-m", "venv", venv_dir])
        print("✓ Виртуальное окружение создано")
        return True
    except subprocess.CalledProcessError as e:
        print(f"✗ Ошибка при создании venv: {e}")
        return False


def install_packages():
    """Установка необходимых пакетов"""
    print("\n3. Установка пакетов...")

    # Определяем путь к pip в зависимости от ОС
    if platform.system() == "Windows":
        python_path = os.path.join('.venv', 'Scripts', 'python')
    else:
        python_path = os.path.join('.venv', 'bin', 'python')

    # Пакеты для установки
    packages = [
        'pandas>=1.5.0',
        'openpyxl>=3.0.0'
    ]

    for package in packages:
        print(f"\nУстановка {package}...")
        try:
            if os.path.exists('.venv'):
                # Устанавливаем в виртуальное окружение
                subprocess.check_call([python_path, "-m", "pip", "install", package])
            else:
                # Устанавливаем глобально
                subprocess.check_call([sys.executable, "-m", "pip", "install", package])
            print(f"✓ {package} установлен")
        except subprocess.CalledProcessError as e:
            print(f"✗ Ошибка при установке {package}: {e}")
            print("Попробуйте установить вручную:")
            if os.path.exists('.venv'):
                print(f"  {python_path} -m pip install {package}")
            else:
                print(f"  pip install {package}")
            return False

    return True


def verify_installation():
    """Проверка установки"""
    print("\n4. Проверка установки...")

    # Пытаемся импортировать библиотеки
    test_script = """
try:
    import pandas as pd
    import openpyxl
    print("✓ Все библиотеки успешно импортированы")
    print(f"  pandas версия: {pd.__version__}")
    print(f"  openpyxl версия: {openpyxl.__version__}")
except ImportError as e:
    print(f"✗ Ошибка импорта: {e}")
    return False
return True
    """

    # Определяем путь к python
    if platform.system() == "Windows":
        python_path = os.path.join('.venv', 'Scripts', 'python')
    else:
        python_path = os.path.join('.venv', 'bin', 'python')

    if os.path.exists('.venv'):
        result = subprocess.run([python_path, "-c", test_script], capture_output=True, text=True)
    else:
        result = subprocess.run([sys.executable, "-c", test_script], capture_output=True, text=True)

    print(result.stdout)
    return result.returncode == 0


def print_instructions():
    """Вывод инструкций"""
    print("\n" + "=" * 70)
    print("ИНСТРУКЦИЯ ПО ЗАПУСКУ:")
    print("=" * 70)

    # Определяем команды для активации venv
    if platform.system() == "Windows":
        activate_cmd = ".venv\\Scripts\\activate"
        run_cmd = "python fortigate_analyzer.py"
    else:
        activate_cmd = "source .venv/bin/activate"
        run_cmd = "python3 fortigate_analyzer.py"

    if os.path.exists('.venv'):
        print("\n1. Активируйте виртуальное окружение:")
        print(f"   {activate_cmd}")

    print("\n2. Поместите файл конфигурации FortiGate в папку проекта")
    print("   Или укажите полный путь при запуске")

    print("\n3. Запустите анализатор:")
    print(f"   {run_cmd}")

    print("\n4. Следуйте инструкциям в программе")
    print("\n" + "=" * 70)


def main():
    """Основная функция"""
    print_header()

    # Проверяем версию Python
    if not check_python_version():
        return

    # Создаем виртуальное окружение
    check_and_create_venv()

    # Устанавливаем пакеты
    if install_packages():
        # Проверяем установку
        if verify_installation():
            print("\n" + "=" * 70)
            print("✅ УСТАНОВКА ЗАВЕРШЕНА УСПЕШНО!")
        else:
            print("\n" + "=" * 70)
            print("⚠️ УСТАНОВКА ЗАВЕРШЕНА С ПРЕДУПРЕЖДЕНИЯМИ")
    else:
        print("\n" + "=" * 70)
        print("❌ УСТАНОВКА НЕ УДАЛАСЬ")

    print_instructions()


if __name__ == "__main__":
    main()
