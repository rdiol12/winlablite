; The winlab installer (Inno Setup 6.3 or later; free, commercial use allowed).
; packaging\build-exe.ps1 compiles it after building winlab.exe:
;
;   ISCC /DAppVersion=0.2.0 /DRepoDir=<checkout> /DDistDir=<checkout>\dist
;        /DIconFile=<checkout>\build\winlab.ico [/DSIGN /Swinlabsign=<command>] winlab.iss
;
; What it does
;   * per-user by default (no administrator prompt); "Install for all users"
;     is offered and then asks for administrator rights
;   * puts winlab.exe and the three documents in the program folder, which
;     winlab never writes to
;   * asks where winlab keeps the machines (tens of GB; the default is the
;     drive with room) and writes that folder into winlab-home.txt next to
;     the exe (winlab/paths.py reads it)
;   * an optional product key page (/KEY=... on the command line for a
;     silent install): a typed key is checked against its check character
;     (the same sum winlab/licensing/keys.py uses), an empty one asks first;
;     the key goes into product-key.txt in that data folder and winlab
;     activates from it once, on first start (licensing/client.py)
;   * over an existing winlab it asks: Upgrade (the default: same program
;     folder, data folder, settings and key, no other page) or New
;     installation (choose the folder and key again; winlab.local.toml is
;     set aside as winlab.local.toml.old; machines and downloads are kept).
;     /CLEAN=1 picks New installation on a silent install. A third choice,
;     Uninstall winlab, runs the installed uninstaller and closes setup
;   * Start menu entry, optional desktop icon, optional PATH entry
;   * /RELAUNCH=1 (what winlab's own updater passes with /VERYSILENT) starts
;     winlab again when the update is installed
;   * uninstall stops running labs, removes the program, and asks before it
;     deletes the machines and downloads (a silent uninstall keeps them)
;
; What it never does: carry QEMU, drivers, DSC modules or any Microsoft file.
; Those are fetched on the customer's PC by winlab itself (LICENSING.md).
;
; Signing: when build-exe.ps1 has a certificate it passes /DSIGN and a sign
; command named winlabsign (packaging\sign.ps1); Inno then signs both the
; setup and the uninstaller. Without one the installer is built unsigned.

#ifndef AppVersion
  #define AppVersion "0.0.0"
#endif
#ifndef RepoDir
  #define RepoDir AddBackslash(SourcePath) + ".."
#endif
#ifndef DistDir
  #define DistDir RepoDir + "\dist"
#endif
#ifndef IconFile
  #define IconFile RepoDir + "\build\winlab.ico"
#endif
; The name in Apps & features and on the signature: set it to the legal name
; on the code-signing certificate when there is one.
#ifndef Publisher
  #define Publisher "winlab"
#endif
; winlab core (build-exe.ps1 -Edition core) names its setup winlab-core-<version>-setup.
#ifndef OutputName
  #define OutputName "winlab-" + AppVersion + "-setup"
#endif

[Setup]
; Never change AppId: upgrades and the uninstaller find winlab by it.
AppId={{627501DE-27F2-4756-BB58-417EE187FE58}
AppName=winlab
AppVersion={#AppVersion}
AppVerName=winlab {#AppVersion}
AppPublisher={#Publisher}
VersionInfoVersion={#AppVersion}
VersionInfoDescription=winlab installer
DefaultDirName={autopf}\winlab
DisableDirPage=yes
DefaultGroupName=winlab
DisableProgramGroupPage=yes
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=dialog commandline
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
; Windows 10 1809: bsdtar with zstd and the Windows Hypervisor Platform.
MinVersion=10.0.17763
OutputDir={#DistDir}
OutputBaseFilename={#OutputName}
SetupIconFile={#IconFile}
UninstallDisplayIcon={app}\winlab.exe
UninstallDisplayName=winlab
WizardStyle=modern
Compression=lzma2/max
SolidCompression=yes
CloseApplications=yes
RestartApplications=no
ChangesEnvironment=yes
InfoBeforeFile={#RepoDir}\packaging\installer-before.txt
#if FileExists(RepoDir + "\EULA.txt")
LicenseFile={#RepoDir}\EULA.txt
#endif
#ifdef SIGN
SignTool=winlabsign
SignedUninstaller=yes
#endif

[Languages]
Name: "en"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "Put a winlab icon on the desktop"; GroupDescription: "Shortcuts:"
Name: "addtopath"; Description: "Let me type winlab in a command prompt (adds it to PATH)"; GroupDescription: "Command line:"; Flags: unchecked

[Files]
Source: "{#DistDir}\winlab.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#RepoDir}\README.md"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#RepoDir}\LICENSING.md"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#RepoDir}\CURRICULUM.md"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#RepoDir}\EULA*.txt"; DestDir: "{app}"; Flags: ignoreversion skipifsourcedoesntexist

[Icons]
Name: "{autoprograms}\winlab"; Filename: "{app}\winlab.exe"; Comment: "Your Windows Server lab"
Name: "{autodesktop}\winlab"; Filename: "{app}\winlab.exe"; Comment: "Your Windows Server lab"; Tasks: desktopicon

[Run]
Filename: "{app}\winlab.exe"; Description: "Open winlab now"; Flags: nowait postinstall skipifsilent runasoriginaluser
; After an update winlab installed itself (silent, /RELAUNCH=1): start it again.
Filename: "{app}\winlab.exe"; Flags: nowait runasoriginaluser; Check: RelaunchAfterUpdate

[UninstallRun]
; Machines first (QEMU runs from the data folder), then winlab's own desktop.
Filename: "{app}\winlab.exe"; Parameters: "lab down --all"; Flags: runhidden waituntilterminated; RunOnceId: "StopLabs"
Filename: "{sys}\taskkill.exe"; Parameters: "/F /T /IM winlab.exe /FI ""USERNAME eq {username}"""; Flags: runhidden waituntilterminated; RunOnceId: "CloseWinlab"

[UninstallDelete]
Type: files; Name: "{app}\winlab-home.txt"

[Code]
const
  HomePointer = 'winlab-home.txt';
  DriveFixed = 3;
  KeyAlphabet = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
  UninstallKey = 'Software\Microsoft\Windows\CurrentVersion\Uninstall\{627501DE-27F2-4756-BB58-417EE187FE58}_is1';

var
  ModePage: TInputOptionWizardPage;
  DataDirPage: TInputDirWizardPage;
  KeyPage: TInputQueryWizardPage;
  UninstallDataDir: String;
  QuitQuietly: Boolean;

{ winlab is already on this PC (it left its data folder behind). }
function AlreadyInstalled(): Boolean;
begin
  Result := GetPreviousData('DataDir', '') <> '';
end;

{ Upgrade in place unless the user chose a new installation. }
function IsUpgrade(): Boolean;
begin
  Result := False;
  if not AlreadyInstalled() then
    Exit;
  if WizardSilent() then
    Result := ExpandConstant('{param:CLEAN|0}') <> '1'
  else
    Result := ModePage.Values[0];
end;

{ The key as winlab/licensing/keys.py normalize() reads it: no dashes or
  spaces, upper case, no WLAB prefix, I/L as 1, O as 0, U as V. }
function NormalKey(Raw: String): String;
begin
  Result := Uppercase(Trim(Raw));
  StringChangeEx(Result, '-', '', True);
  StringChangeEx(Result, ' ', '', True);
  if Copy(Result, 1, 4) = 'WLAB' then
    Result := Copy(Result, 5, Length(Result) - 4);
  StringChangeEx(Result, 'I', '1', True);
  StringChangeEx(Result, 'L', '1', True);
  StringChangeEx(Result, 'O', '0', True);
  StringChangeEx(Result, 'U', 'V', True);
end;

{ Twenty characters and the check character keys.py puts last, so a typo
  is caught here and not on the first start. }
function KeyLooksRight(Raw: String): Boolean;
var
  S: String;
  I, P, Total: Integer;
begin
  Result := False;
  S := NormalKey(Raw);
  if Length(S) <> 21 then
    Exit;
  Total := 0;
  for I := 1 to 20 do
  begin
    P := Pos(Copy(S, I, 1), KeyAlphabet);
    if P = 0 then
      Exit;
    Total := (Total + (P - 1) * I) mod 32;
  end;
  if Pos(Copy(S, 21, 1), KeyAlphabet) = 0 then
    Exit;
  Result := Copy(KeyAlphabet, Total + 1, 1) = Copy(S, 21, 1);
end;

function RelaunchAfterUpdate(): Boolean;
begin
  Result := ExpandConstant('{param:RELAUNCH|0}') = '1';
end;

function GetDriveType(lpRootPathName: String): Cardinal;
  external 'GetDriveTypeW@kernel32.dll stdcall';

function GiB(N: Integer): Int64;
begin
  Result := N;
  Result := Result * 1073741824;
end;

function FreeBytes(Dir: String): Int64;
var
  FreeB, TotalB: Int64;
begin
  Result := 0;
  if GetSpaceOnDisk64(ExtractFileDrive(Dir) + '\', FreeB, TotalB) then
    Result := FreeB;
end;

{ %LOCALAPPDATA%\winlab when C: has room; otherwise the fixed drive with the
  most free space. A Windows base is 8-9 GB, a lab of clones a few more. }
function PickDefaultDataDir(): String;
var
  I: Integer;
  Root, Best: String;
  FreeB, TotalB, BestFree: Int64;
begin
  Result := ExpandConstant('{localappdata}\winlab');
  BestFree := FreeBytes(Result);
  if BestFree >= GiB(40) then
    Exit;
  Best := '';
  for I := Ord('C') to Ord('Z') do
  begin
    Root := Chr(I) + ':\';
    if GetDriveType(Root) = DriveFixed then
      if GetSpaceOnDisk64(Root, FreeB, TotalB) then
        if FreeB > BestFree then
        begin
          BestFree := FreeB;
          Best := Root;
        end;
  end;
  if Best <> '' then
    Result := Best + 'winlab';
end;

function ChosenDataDir(): String;
begin
  Result := ExpandConstant('{param:DATADIR}');
  if Result = '' then
    Result := DataDirPage.Values[0];
  Result := RemoveBackslashUnlessRoot(Result);
end;

procedure InitializeWizard();
begin
  ModePage := CreateInputOptionPage(wpInfoBefore,
    'winlab is already installed',
    'Upgrade it where it is, install it again from the start, or remove it?',
    'Choose how to install this version:',
    True, False);
  ModePage.Add('Upgrade (recommended): keep your settings, your product key and the folder with your machines');
  ModePage.Add('New installation: choose the folder and product key again and start with default settings ' +
    '(your machines and downloads stay where they are)');
  ModePage.Add('Uninstall winlab: remove the installed winlab (it asks whether to keep your machines and downloads)');
  ModePage.Values[0] := True;
  DataDirPage := CreateInputDirPage(ModePage.ID,
    'Where should winlab keep your machines?',
    'Lab machines, the Windows bases and downloads go here.',
    'winlab needs about 40 GB in this folder (25 GB if you only use Windows Server). ' +
    'Pick a drive with room.' + #13#10#13#10 +
    'Folder for winlab''s machines and downloads:',
    False, 'winlab');
  DataDirPage.Add('');
  DataDirPage.Values[0] := GetPreviousData('DataDir', PickDefaultDataDir());
  KeyPage := CreateInputQueryPage(DataDirPage.ID,
    'Product key',
    'If you bought winlab, type your product key here. You can also do it later in winlab.',
    'winlab activates with this key the first time it starts (it needs the internet once). ' +
    'Leave it empty to start with the free first lab.');
  KeyPage.Add('Product key (WLAB-XXXXX-XXXXX-XXXXX-XXXXX-X):', False);
end;

{ The installed winlab's uninstaller, per user or for all users. }
function InstalledUninstaller(): String;
begin
  Result := '';
  if not RegQueryStringValue(HKEY_CURRENT_USER, UninstallKey, 'UninstallString', Result) then
    if not RegQueryStringValue(HKEY_LOCAL_MACHINE, UninstallKey, 'UninstallString', Result) then
      Result := '';
  Result := RemoveQuotes(Result);
end;

{ Uninstall winlab from the installer: its own uninstaller does the work
  (stops the labs, asks about the data), then setup closes. }
procedure RunUninstall();
var
  Exe: String;
  Code: Integer;
begin
  Exe := InstalledUninstaller();
  if (Exe = '') or not FileExists(Exe) then
  begin
    MsgBox('winlab''s uninstaller was not found. Remove winlab from Settings > Apps instead.', mbError, MB_OK);
    Exit;
  end;
  if not Exec(Exe, '', '', SW_SHOW, ewWaitUntilTerminated, Code) then
  begin
    MsgBox('The uninstaller did not start: ' + SysErrorMessage(Code), mbError, MB_OK);
    Exit;
  end;
  QuitQuietly := True;
  WizardForm.Close;
end;

procedure CancelButtonClick(CurPageID: Integer; var Cancel, Confirm: Boolean);
begin
  if QuitQuietly then
    Confirm := False;
end;

function ProductKey(): String;
begin
  Result := Trim(ExpandConstant('{param:KEY}'));
  if (Result = '') and (KeyPage <> nil) then
    Result := Trim(KeyPage.Values[0]);
  { A silent install with a mistyped /KEY= starts as the free first lab. }
  if (Result <> '') and not KeyLooksRight(Result) then
    Result := '';
end;

procedure RegisterPreviousData(PreviousDataKey: Integer);
begin
  SetPreviousData(PreviousDataKey, 'DataDir', ChosenDataDir());
end;

function ShouldSkipPage(PageID: Integer): Boolean;
begin
  { The choice is only there over an existing winlab; an upgrade keeps the
    folder and the key it had. }
  Result := ((PageID = ModePage.ID) and not AlreadyInstalled())
    or (((PageID = DataDirPage.ID) or (PageID = KeyPage.ID)) and IsUpgrade());
end;

function NextButtonClick(CurPageID: Integer): Boolean;
var
  Dir: String;
  FreeB: Int64;
begin
  Result := True;
  if (CurPageID = ModePage.ID) and ModePage.Values[2] then
  begin
    RunUninstall();
    Result := False;
    Exit;
  end;
  if CurPageID = KeyPage.ID then
  begin
    if Trim(KeyPage.Values[0]) = '' then
      Result := MsgBox('You did not type a product key.' + #13#10#13#10 +
        'winlab installs and starts with the free first lab; you can type your key later in winlab ' +
        '(Start > Activate winlab).' + #13#10#13#10 + 'Continue without a product key?',
        mbConfirmation, MB_YESNO or MB_DEFBUTTON2) = IDYES
    else if not KeyLooksRight(KeyPage.Values[0]) then
    begin
      MsgBox('This product key is not right: a letter or digit is mistyped or missing.' + #13#10#13#10 +
        'A key looks like WLAB-XXXXX-XXXXX-XXXXX-XXXXX-X. Check it against your purchase email, ' +
        'or leave the box empty to start with the free first lab.', mbError, MB_OK);
      Result := False;
    end;
    Exit;
  end;
  if CurPageID <> DataDirPage.ID then
    Exit;
  Dir := ChosenDataDir();
  if Length(Dir) <= 3 then
  begin
    MsgBox('Pick a folder, not the whole drive: winlab keeps its own folder (for example ' +
      Dir + 'winlab).', mbError, MB_OK);
    Result := False;
    Exit;
  end;
  if not ForceDirectories(Dir) then
  begin
    MsgBox('winlab cannot create or write to this folder:' + #13#10 + Dir + #13#10#13#10 +
      'Pick a folder you own.', mbError, MB_OK);
    Result := False;
    Exit;
  end;
  FreeB := FreeBytes(Dir);
  if (FreeB < GiB(25)) and not WizardSilent() then
    Result := MsgBox('This drive has less than 25 GB free. winlab installs, but the Windows ' +
      'machines will not fit until you free some space.' + #13#10#13#10 + 'Use this folder anyway?',
      mbConfirmation, MB_YESNO or MB_DEFBUTTON2) = IDYES;
end;

{ Written as %LOCALAPPDATA%\winlab when it is the default, so an install for
  all users still gives every user a folder of their own. }
procedure WritePointer(Dir: String);
var
  Lines: TArrayOfString;
begin
  if CompareText(Dir, ExpandConstant('{localappdata}\winlab')) = 0 then
    Dir := '%LOCALAPPDATA%\winlab';
  SetArrayLength(Lines, 2);
  Lines[0] := '# winlab keeps its machines and downloads here (chosen at installation).';
  Lines[1] := Dir;
  SaveStringsToUTF8File(ExpandConstant('{app}\' + HomePointer), Lines, False);
end;

function PathKeyRoot(): Integer;
begin
  if IsAdminInstallMode() then
    Result := HKEY_LOCAL_MACHINE
  else
    Result := HKEY_CURRENT_USER;
end;

function PathKey(): String;
begin
  if IsAdminInstallMode() then
    Result := 'SYSTEM\CurrentControlSet\Control\Session Manager\Environment'
  else
    Result := 'Environment';
end;

procedure AddToPath(Dir: String);
var
  Paths: String;
begin
  if not RegQueryStringValue(PathKeyRoot(), PathKey(), 'Path', Paths) then
    Paths := '';
  if Pos(';' + Uppercase(Dir) + ';', ';' + Uppercase(Paths) + ';') > 0 then
    Exit;
  if (Paths <> '') and (Copy(Paths, Length(Paths), 1) <> ';') then
    Paths := Paths + ';';
  RegWriteExpandStringValue(PathKeyRoot(), PathKey(), 'Path', Paths + Dir);
end;

procedure RemoveFromPath(Dir: String);
var
  Paths: String;
begin
  if not RegQueryStringValue(PathKeyRoot(), PathKey(), 'Path', Paths) then
    Exit;
  Paths := ';' + Paths + ';';
  if StringChangeEx(Paths, ';' + Dir + ';', ';', True) = 0 then
    Exit;
  Paths := Copy(Paths, 2, Length(Paths) - 2);
  RegWriteExpandStringValue(PathKeyRoot(), PathKey(), 'Path', Paths);
end;

procedure CurStepChanged(CurStep: TSetupStep);
var
  Dir: String;
  Key: TArrayOfString;
begin
  if CurStep <> ssPostInstall then
    Exit;
  Dir := ChosenDataDir();
  ForceDirectories(Dir);
  { A new installation over an old one starts with default settings; the
    old ones are kept beside it, not deleted. }
  if AlreadyInstalled() and not IsUpgrade() and FileExists(Dir + '\winlab.local.toml') then
  begin
    DeleteFile(Dir + '\winlab.local.toml.old');
    RenameFile(Dir + '\winlab.local.toml', Dir + '\winlab.local.toml.old');
  end;
  WritePointer(Dir);
  SetArrayLength(Key, 1);
  Key[0] := ProductKey();
  if Key[0] <> '' then
    SaveStringsToUTF8File(Dir + '\product-key.txt', Key, False);
  if WizardIsTaskSelected('addtopath') then
    AddToPath(ExpandConstant('{app}'));
end;

{ The data folder from winlab-home.txt, read before the uninstaller removes it. }
function ReadDataDir(): String;
var
  Lines: TArrayOfString;
  I: Integer;
  Line: String;
begin
  Result := '';
  if not LoadStringsFromFile(ExpandConstant('{app}\' + HomePointer), Lines) then
    Exit;
  for I := 0 to GetArrayLength(Lines) - 1 do
  begin
    Line := Trim(Lines[I]);
    if (Line <> '') and (Copy(Line, 1, 1) <> '#') then
    begin
      StringChangeEx(Line, '%LOCALAPPDATA%', ExpandConstant('{localappdata}'), True);
      Result := RemoveBackslashUnlessRoot(Line);
      Exit;
    end;
  end;
end;

{ Only what winlab itself made: never the folder the user picked as a whole. }
procedure DeleteWinlabData(Dir: String);
begin
  DelTree(Dir + '\images', True, True, True);
  DelTree(Dir + '\runtime', True, True, True);
  DelTree(Dir + '\var', True, True, True);
  DelTree(Dir + '\content', True, True, True);
  DeleteFile(Dir + '\winlab.local.toml');
  DeleteFile(Dir + '\product-key.txt');
  RemoveDir(Dir);
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  if CurUninstallStep = usUninstall then
  begin
    UninstallDataDir := ReadDataDir();
    RemoveFromPath(ExpandConstant('{app}'));
  end;
  if CurUninstallStep = usPostUninstall then
  begin
    if UninstallSilent() or (UninstallDataDir = '') or (Length(UninstallDataDir) <= 3) then
      Exit;
    if not DirExists(UninstallDataDir + '\var') and not DirExists(UninstallDataDir + '\content') then
      Exit;
    if MsgBox('winlab is removed. Also delete your labs and downloads?' + #13#10#13#10 +
      UninstallDataDir + #13#10#13#10 +
      'This deletes every lab machine, checkpoint, imported Windows ISO and downloaded component ' +
      'in that folder. It cannot be undone. Choose No to keep them for a later install.',
      mbConfirmation, MB_YESNO or MB_DEFBUTTON2) = IDYES then
      DeleteWinlabData(UninstallDataDir);
  end;
end;
