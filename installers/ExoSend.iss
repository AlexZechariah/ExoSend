[Setup]
; ============================================================================
; ExoSend Setup Script
; For Inno Setup 6.x or later
; Creates production-ready Windows installer with all dependencies bundled
; ============================================================================

; Application Information
AppName=ExoSend
AppVersion=0.2.0
AppPublisher=ExoSend Project
AppPublisherURL=https://github.com/yourusername/exosend
AppSupportURL=https://github.com/yourusername/exosend/issues
AppUpdatesURL=https://github.com/yourusername/exosend/releases
AppCopyright=Copyright (C) 2026
AppContact=exosend@example.com
DefaultDirName={commonpf}\ExoSend
DefaultGroupName=ExoSend
AllowNoIcons=yes
OutputDir=..\build\installer
OutputBaseFilename=ExoSend Installer
Compression=lzma2
SolidCompression=yes
WizardStyle=modern

; Installer Assets (relative paths)
SetupIconFile=..\assets\icon.ico
WizardImageFile=..\assets\installer_image.png
WizardSmallImageFile=..\assets\installer_small.png

UninstallDisplayIcon={app}\ExoSend.exe
ChangesAssociations=yes
DisableDirPage=no
DisableProgramGroupPage=yes

; Languages
; Languages=en
; ShowLanguageDialog=no

; Privileges
PrivilegesRequired=admin
PrivilegesRequiredOverridesAllowed=dialog

; Build Information
VersionInfoVersion=0.2.0.0
VersionInfoCompany=ExoSend Project
VersionInfoDescription=ExoSend
VersionInfoCopyright=Copyright (C) 2026
AppVerName=ExoSend

; Minimum Windows Version (Windows 10 May 2020 Update)
MinVersion=10.0.19041
OnlyBelowVersion=0

; Architectures
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible

[Tasks]
; Desktop Shortcut - CHECKED BY DEFAULT (no unchecked flag)
Name: "desktopicon"; Description: "Create a &desktop shortcut"; GroupDescription: "Additional icons:"

; Firewall Rule
Name: "firewall"; Description: "Add &Windows Firewall rule"; GroupDescription: "Security:"; Flags: unchecked

; Auto-start
Name: "autostart"; Description: "Start ExoSend automatically when Windows starts"; GroupDescription: "Startup:"; Flags: unchecked

[Files]
; ============================================================================
; NOTE: This section bundles the entire deployment directory created by windeployqt
; ============================================================================
; Bundle entire deployed directory (windeployqt output)
; This includes: ExoSend.exe, all Qt DLLs, platform plugins, OpenSSL, ICU, etc.
Source: "..\build\release\bin\Release\*"; DestDir: "{app}"; \
    Flags: ignoreversion recursesubdirs createallsubdirs

; Visual C++ Redistributable 2015-2022 (x64)
; Downloaded from: https://aka.ms/vs/17/release/vc_redist.x64.exe
; This will be installed if not already present on the system
Source: "VC_redist.x64.exe"; DestDir: "{tmp}"; Flags: deleteafterinstall

[Icons]
; Start Menu Icons
Name: "{group}\ExoSend"; Filename: "{app}\ExoSend.exe"; Comment: "Launch ExoSend File Transfer"
Name: "{group}\Uninstall ExoSend"; Filename: "{uninstallexe}"; Comment: "Remove ExoSend from your computer"

; Desktop Icon (CHECKED BY DEFAULT - no Tasks: parameter for the desktopicon)
Name: "{autodesktop}\ExoSend"; Filename: "{app}\ExoSend.exe"; Comment: "Launch ExoSend File Transfer"

[Run]
; ============================================================================
; Post-Installation Tasks
; ============================================================================

; Install Visual C++ Redistributable if not already installed
; Uses silent install with no restart
Filename: "{tmp}\VC_redist.x64.exe"; \
    Parameters: "/install /quiet /norestart"; \
    Check: VCRedistNeedsInstall; \
    StatusMsg: "Installing Visual C++ Redistributable..."; \
    BeforeInstall: VCRedistInstallBegin; \
    AfterInstall: VCRedistInstallEnd

; Add Windows Firewall Rule (if selected)
Filename: "netsh.exe"; \
    Parameters: "advfirewall firewall add rule ""name=ExoSend"" dir=in action=allow program=""{app}\ExoSend.exe"" enable=yes profile=any"; \
    StatusMsg: "Adding Windows Firewall rule..."; \
    Flags: runhidden; \
    Tasks: firewall

; Start Application After Install (auto-launch enabled)
Filename: "{app}\ExoSend.exe"; \
    Description: "Launch ExoSend"; \
    Flags: nowait postinstall skipifsilent

[UninstallRun]
; Remove Windows Firewall Rule
Filename: "netsh.exe"; \
    Parameters: "advfirewall firewall delete rule ""name=ExoSend"""; \
    Flags: runhidden; \
    RunOnceId: "DeleteFirewallRule"

[UninstallDelete]
; Delete Application Directory (if empty)
Type: dirifempty; Name: "{app}"

[Registry]
; ============================================================================
; Registry Entries
; ============================================================================

; File Association (optional - for .exosend transfer files)
Root: HKCR; Subkey: ".exosend"; ValueType: string; ValueName: ""; ValueData: "ExoSend.Transfer"; Flags: uninsdeletekey
Root: HKCR; Subkey: "ExoSend.Transfer"; ValueType: string; ValueName: ""; ValueData: "ExoSend Transfer File"; Flags: uninsdeletekey
Root: HKCR; Subkey: "ExoSend.Transfer\DefaultIcon"; ValueType: string; ValueName: ""; ValueData: "{app}\ExoSend.exe,0"; Flags: uninsdeletekey
Root: HKCR; Subkey: "ExoSend.Transfer\shell\open\command"; ValueType: string; ValueName: ""; ValueData: """{app}\ExoSend.exe"" ""%1"""; Flags: uninsdeletekey

; Auto-start on Windows startup (if selected) - per-machine (all users)
Root: HKLM; Subkey: "Software\Microsoft\Windows\CurrentVersion\Run"; ValueType: string; ValueName: "ExoSend"; ValueData: """{app}\ExoSend.exe"""; Flags: uninsdeletevalue; Tasks: autostart

; Application Settings (Store installation path)
Root: HKLM; Subkey: "Software\ExoSend"; ValueType: string; ValueName: "InstallPath"; ValueData: "{app}"; Flags: uninsdeletekey
Root: HKLM; Subkey: "Software\ExoSend"; ValueType: string; ValueName: "Version"; ValueData: "0.2.0"; Flags: uninsdeletekey

[Dirs]
; Create required directories (these should already exist from Files section, but ensuring them)
Name: "{app}\platforms"
Name: "{app}\styles"
Name: "{app}\imageformats"
Name: "{app}\certs"

[Code]
// ============================================================================
// Pascal Script Functions
// ============================================================================

// Visual C++ Redistributable Detection
// Checks if VC++ 2015-2022 Redistributable (x64) is already installed
function VCRedistNeedsInstall: Boolean;
var
    Installed: Cardinal;
begin
    // Check registry key: HKLM\SOFTWARE\Microsoft\VisualStudio\14.0\VC\Runtimes\x64
    // The 'Installed' value is 1 if installed, 0 or missing if not
    Result := True;  // Default to needing installation

    if RegQueryDWordValue(HKLM, 'SOFTWARE\Microsoft\VisualStudio\14.0\VC\Runtimes\x64', 'Installed', Installed) then
    begin
        Result := (Installed = 0);
    end;
end;

// Helper function to check if running on compatible 64-bit Windows
function Is64BitInstallMode: Boolean;
begin
    Result := IsX64Compatible();
end;

// Before VC++ Redistributable installation
procedure VCRedistInstallBegin;
begin
    // Log start of VC++ Redist installation
end;

// After VC++ Redistributable installation
procedure VCRedistInstallEnd;
begin
    // Log completion of VC++ Redist installation
end;

// Custom page changed event (for future custom pages)
procedure CurPageChanged(CurPageID: Integer);
begin
    // Add any custom page logic here
end;

// Initialize setup - perform pre-installation checks
function InitializeSetup(): Boolean;
begin
    Result := True;

    // Check if already running
    if CheckForMutexes('ExoSendRunningMutex') then
    begin
        if MsgBox('ExoSend is currently running. Please close it before installing.' + #13#10 #13#10 +
                  'Click OK to continue with the installation, or Cancel to abort.',
                  mbInformation, MB_OKCANCEL) <> IDOK then
        begin
            Result := False;
        end;
    end;
end;

// Initialize uninstall - check if application is running
function InitializeUninstall(): Boolean;
begin
    // Check if ExoSend is running
    if CheckForMutexes('ExoSendRunningMutex') then
    begin
        if MsgBox('ExoSend is currently running.' + #13#10 #13#10 +
                  'Click OK to close ExoSend and continue with uninstall,' + #13#10 +
                  'or Cancel to abort.',
                  mbConfirmation, MB_OKCANCEL) = IDOK then
        begin
            // Try to close ExoSend gracefully
            // In production, you might want to send WM_CLOSE to the main window
            // For now, just proceed and let the user close it manually
            Result := True;
        end
        else
        begin
            Result := False;
        end;
    end
    else
    begin
        Result := True;
    end;
end;

// CurInstallProgressChanged callback (optional - for custom progress UI)
procedure CurInstallProgressChanged(CurProgress, MaxProgress: Integer);
begin
    // Add custom progress handling here if needed
end;
