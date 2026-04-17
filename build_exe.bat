@echo off
setlocal

python -m pip install -r requirements.txt
if errorlevel 1 (
  echo Failed to install requirements.
  exit /b 1
)

pyinstaller --noconfirm --onefile --windowed --icon assets/forti-analyzer-icon.ico --name FortiGateAnalyzer app.py
if errorlevel 1 (
  echo Build failed.
  exit /b 1
)

echo Build complete: dist\FortiGateAnalyzer.exe
endlocal
