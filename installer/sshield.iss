; Inno Setup script. Built in CI: iscc /DAppVersion=1.2.3 installer\sshield.iss
#ifndef AppVersion
  #define AppVersion "0.0.0"
#endif

[Setup]
AppId={{6F1B8C0E-4D8A-4E43-9C57-5A3B7E2D9A11}
AppName=sshield
AppVersion={#AppVersion}
AppPublisher=sshield
DefaultDirName={autopf}\sshield
DefaultGroupName=sshield
UninstallDisplayIcon={app}\sshield.exe
OutputDir=..\dist
OutputBaseFilename=sshield-windows-x64-setup
Compression=lzma2
SolidCompression=yes
ArchitecturesInstallIn64BitMode=x64compatible
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=dialog
CloseApplications=yes
RestartApplications=yes

[Files]
Source: "..\target\release\sshield.exe"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\sshield"; Filename: "{app}\sshield.exe"
Name: "{autodesktop}\sshield"; Filename: "{app}\sshield.exe"; Tasks: desktopicon

[Tasks]
Name: "desktopicon"; Description: "Create a desktop shortcut"; Flags: unchecked

[Run]
Filename: "{app}\sshield.exe"; Description: "Launch sshield"; Flags: nowait postinstall skipifsilent
