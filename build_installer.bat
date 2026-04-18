@echo off
setlocal

python -m pip install -r requirements.txt
if errorlevel 1 (
  echo Failed to install requirements.
  exit /b 1
)

pyinstaller --noconfirm --onefile --windowed --icon assets/forti-analyzer-icon.ico --name FortiGateAnalyzer app.py
if errorlevel 1 (
  echo PyInstaller build failed.
  exit /b 1
)

if not exist "%ProgramFiles(x86)%\Inno Setup 6\ISCC.exe" (
  echo Inno Setup 6 not found. Install it from https://jrsoftware.org/isinfo.php
  exit /b 1
)

"%ProgramFiles(x86)%\Inno Setup 6\ISCC.exe" "installer\FortiGateAnalyzer.iss"
if errorlevel 1 (
  echo Installer build failed.
  exit /b 1
)

echo Build complete:
echo - dist\FortiGateAnalyzer.exe
echo - dist\FortiGateAnalyzer-Setup.exe
endlocal
