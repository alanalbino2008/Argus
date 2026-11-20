; Windows installer for the Argus desktop app (Inno Setup 6).
;
;   iscc /DAppVersion=1.55.0 /DSourceDir=..\..\dist\Argus /DOutputDir=..\..\dist packaging\desktop\argus.iss
;
; Installs for the current user only (no administrator rights needed) into
; %LOCALAPPDATA%\Programs\Argus. Cases live in %APPDATA%\Argus and are never removed by an
; update or an uninstall.

#ifndef AppVersion
  #define AppVersion "0.0.0"
#endif
#ifndef SourceDir
  #define SourceDir "..\..\dist\Argus"
#endif
#ifndef OutputDir
  #define OutputDir "..\..\dist"
#endif

[Setup]
AppId={{F34DE521-C7A5-4482-8AD2-E953565AB41B}
AppName=Argus
AppVersion={#AppVersion}
AppVerName=Argus {#AppVersion}
AppPublisher=Argus
DefaultDirName={localappdata}\Programs\Argus
DefaultGroupName=Argus
DisableProgramGroupPage=yes
DisableDirPage=yes
PrivilegesRequired=lowest
OutputDir={#OutputDir}
OutputBaseFilename=Argus-Setup-{#AppVersion}
SetupIconFile=..\..\build\icons\argus.ico
UninstallDisplayIcon={app}\Argus.exe
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0
CloseApplications=force
RestartApplications=no

[Tasks]
Name: "desktopicon"; Description: "Put an Argus icon on the desktop"; GroupDescription: "Shortcuts:"

[Files]
Source: "{#SourceDir}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[InstallDelete]
; an update replaces the program completely (never the cases, which live in %APPDATA%\Argus)
Type: filesandordirs; Name: "{app}\_internal"

[Icons]
Name: "{group}\Argus"; Filename: "{app}\Argus.exe"
Name: "{userdesktop}\Argus"; Filename: "{app}\Argus.exe"; Tasks: desktopicon

[Run]
Filename: "{app}\Argus.exe"; Description: "Open Argus now"; Flags: nowait postinstall skipifsilent

[UninstallRun]
; close a running Argus before removing it
Filename: "{cmd}"; Parameters: "/C taskkill /IM Argus.exe /F"; Flags: runhidden; RunOnceId: "StopArgus"

[Messages]
FinishedLabel=Argus is installed. Open it from the Argus icon: it runs in your web browser, only on this computer.
