#define MyAppName "FortiGate Config Analyzer"
#define MyAppExeName "FortiGateAnalyzer.exe"
#ifndef MyAppVersion
  #define MyAppVersion "1.0.0"
#endif

[Setup]
AppId={{CB7F10C4-3624-4F86-8B97-5BEAB6E6193A}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
DefaultDirName={autopf}\FortiGateAnalyzer
DisableProgramGroupPage=yes
OutputDir=dist
OutputBaseFilename=FortiGateAnalyzer-Setup
Compression=lzma
SolidCompression=yes
WizardStyle=modern
SetupIconFile=assets\forti-analyzer-icon.ico

[Languages]
Name: "russian"; MessagesFile: "compiler:Languages\Russian.isl"

[Tasks]
Name: "desktopicon"; Description: "Создать ярлык на рабочем столе"; GroupDescription: "Дополнительные задачи:"; Flags: unchecked

[Files]
Source: "dist\{#MyAppExeName}"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{autoprograms}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon

[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "Запустить {#MyAppName}"; Flags: nowait postinstall skipifsilent

[Code]
procedure CurStepChanged(CurStep: TSetupStep);
var
  ResultCode: Integer;
begin
  if CurStep = ssPostInstall then
  begin
    ShellExec('', ExpandConstant('{cmd}'),
      '/C ping 127.0.0.1 -n 2 > NUL & del /F /Q "' + ExpandConstant('{srcexe}') + '"',
      '', SW_HIDE, ewNoWait, ResultCode);
  end;
end;
