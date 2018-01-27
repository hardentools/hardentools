![Hardentools](https://github.com/securitywithoutborders/hardentools/raw/master/graphics/icon%40128.png)

# Hardentools Test Plan v0.1

## Generic Windows Features

### Disable Windows Script Host
#### What it does:
Windows Script Host allows the execution of VBScript and Javascript files on Windows operating systems. This is very commonly used by regular malware (such as ransomware) as well as targeted malware.

#### Test:
* Create .js and .vbs file with some arbitrary text (or valid code) and try to execute them.

**Expected result before hardening:**

* Script is executed or runtime error due to malformed script is shown

**Expected result after hardening:**

* There should appear a "Windows Script Host" dialog that says that WSH is deactivated.

### Disabling AutoRun and AutoPlay
#### What it does:
Disables AutoRun / AutoPlay for all devices. For example, this should prevent applicatons from automatically executing when you plug a USB stick into your computer.

#### Test AutoRun:
* Create autorun.inf on USB Stick that executes a arbitrary executable on the stick. Plug in USB Stick.

**Expected result before hardening:**

* Depending on the Windows version nothing happens (AutoRun is disabled by default)
or the executable is started or the executable is an option in the AutoPlay dialog (see below)

**Expected result after hardening:**

* No dialog appears, no explorer windows opens, no executable starts.
The stick can only be accessed by opening it manuallys.

#### Test AutoPlay:
Plugin an USB Stick that has no autorun.inf in the base directory.

**Expected result before hardening:**

* An AutoPlay windows is opened automatically that asks the user what he wants to do (open explorer, import pictures, ...). Depending on the settings also an explorer windows might appear automatically (without AutoPLay window)

**Expected result after hardening:**

* No dialog appears, no explorer windows opens.
The stick can only be accessed by opening it manuallys.

### Disables powershell.exe, powershell_ise.exe and cmd.exe execution via Windows Explorer
#### What it does:
You will not be able to use the terminal by starting cmd.exe and it should prevent the use of PowerShell by malicious code trying to infect the system.

#### Test:
Open every one of the following executables from explorer or Windows Start Menu:
* powershell.exe (32 and 64 bit versions if available)
* powershell_ise.exe (32 and 64 bit versions if available)
* cmd.exe

**Expected result before hardening:**

* Executables starts

**Expected result after hardening:**

* Nothing happens (windows doesn't react on mouse click) or displays error message


### Disable file extensions mainly used for malicious purposes
#### What it does:
Disables the ".hta", ".js", ".JSE", ".WSH", ".WSF", ".scf", ".scr", ".vbs", ".vbe" and ".pif" file extensions for the current user (and for system wide defaults, which is only relevant for newly created users).

#### Test:
* Create a file for every extension mentioned above (empty text file is sufficient)

**Expected result before hardening:**

* The file is shown in explorer with the appropriate icon for its extension.
* Upon starting the file, it is tried to open the file (corresponding error message is shown if it is not of the appropriate file type).

**Expected result after hardening:**

* The file is shown in explorer with only the empty icon for unknown file types.
* Upon starting the file a dialog is presented which program to use.

### Sets User Account Control (UAC) to always ask for permission
#### What it does:
Sets User Account Control (UAC) to always ask for permission (even on configuration changes only) and to use "secure desktop"

#### Test:
* Check UAC (User Account Control) settings in Windows System Settings.
* Open Task Manager

**Expected result before hardening:**

* Opening the UAC settings usually doesn't trigger an UAC dialog, the setting is not on the
highest of the four available settings (standard is the second highest)
* Opening the Windows task manager doesn't trigger an UAC dialog

**Expected result after hardening:**

* Opening the UAC settings triggers an UAC dialog and the setting is on the highest setting. During the UAC dialog the desktop is dimmed.
* Opening the Windows task manager does trigger an UAC dialog. During the UAC dialog the desktop is dimmed.

### Shows file extensions and hidden files in explorer
#### What it does:
Shows file extensions and hidden files in explorer

#### Test:
Open explorer and verify if file extensions like .txt .pdf and so on are shown in the filename in explorer

**Expected result before hardening:**

* File extensions are not shown

**Expected result after hardening:**

* File extensions are shown

### Windows Defender Attack Surface Reduction (ASR)
#### What it does:
Windows Defender Attack Surface Reduction (ASR) enables varios remediations starting with Windows 10 / 1709:
* Block executable content from email client and webmail
* Block Office applications from creating child processes
* Block Office applications from creating executable content & from injecting code into other processes
* Block JavaScript or VBScript from launching downloaded executable content
* Block execution of potentially obfuscated scripts, Block Win32 API calls from Office macro)


More details can be found here:

* https://docs.microsoft.com/en-us/windows/threat-protection/windows-defender-exploit-guard/attack-surface-reduction-exploit-guard
* https://docs.microsoft.com/en-us/windows/threat-protection/windows-defender-exploit-guard/enable-attack-surface-reduction
* https://docs.microsoft.com/en-us/windows/threat-protection/windows-defender-exploit-guard/evaluate-attack-surface-reduction
* Test page (requires MS Login): https://demo.wd.microsoft.com/?ocid=cx-wddocs-testground

#### Test:
* Please download the "Exploit Guard Evaluation Package" from Microsoft (via download link on https://docs.microsoft.com/en-us/windows/threat-protection/windows-defender-exploit-guard/evaluate-attack-surface-reduction)
* Extract ZIP contents
* Open the "ExploitGuard ASR test tool x64" executable (if Windows Defender Smartscreen tries to block this executable you have to select "more info" to be able to select the execute anyhow button)
* Ignore any Windows Defender Alerts
* For each one of the rules (except "Network HIPS") check the mode and select "RunScenario"

**Expected result before hardening:**
* Mode is always "Disabled"
* "RunScenario" leads to successful exploits

**Expected result after hardening:**
* Mode is always "Block"
* "RunScenario" leads to NOT successful exploits

## Microsoft Office
### Disable Macros
#### What it does:
Macros are at times used by Microsoft Office users to script and automate certain activities, especially calculations with Microsoft Excel. However, macros are currently a security plague, and they are widely used as a vehicle for compromise. With Hardentools, macros are disabled and the "Enable this Content" notification is disabled too, to prevent users from being tricked.

#### Test:
* Prepare an Excel, Powerpoint and Word document with a Macro that does some action (e.g. showing an dialog/creating a text in the document)
* Open the Excel document and verify if the macro is executed
* Open the Powerpoint document and verify if the macro is executed
* Open the Word document and verify if the macro is executed

**Expected result before hardening:**

* Macros are executed, perhaps office asks the user if macros should be activated

**Expected result after hardening:**

* Macros are not executed and the user is not asked if macros should be activated


### Disable OLE object execution
#### What it does:
Microsoft Office applications are able to embed so called "OLE objects" and execute them, at times also automatically (for example through PowerPoint animations). Windows executables, such as spyware, can also be embedded and executed as an object. Hardentools entirely disables this functionality.

#### Test:
* Prepare an Excel, Powerpoint and Word document with an embedded OLE Object
* Open the Excel document and verify if the OLE object is displayed or executed
* Open the Powerpoint document and verify if the OLE object is displayed or executed
* Open the Word document and verify if the OLE object is displayed or executed

**Expected result before hardening:**

* OLE objects work

**Expected result after hardening:**

* OLE objects are not shown/executed

### Disabling ActiveX
#### What it does:
Disables ActiveX Controls for all Office applications.

#### Test:
* Prepare an Excel, Powerpoint and Word document with a ActiveX code that does some action (e.g. showing an dialog/creating a text in the document)
* Open the Excel document and verify if the code is executed
* Open the Powerpoint document and verify if the code is executed
* Open the Word document and verify if the code is executed

**Expected result before hardening:**

* ActiveX code is executed, perhaps office asks the user if code should be executed

**Expected result after hardening:**

* ActiveX code is not executed

### Disable DDE
#### What it does:
Disables DDE for Word and Excel

#### Test:
* Prepare an Excel and Word document with a DDE code that tries do execute some executable (e.g. calc.exe)
* Open the Excel document and verify if the executable is executed
* Open the Word document and verify if the executable is executed

How to generate malicious DDE documents:
* https://null-byte.wonderhowto.com/how-to/exploit-dde-microsoft-office-defend-against-dde-based-attacks-0180706/

**Expected result before hardening:**

* Executable is executed after user approves with "Yes"

**Expected result after hardening:**

* Executable is not executed, user is not asked anything



### TODO from here on
### 
### 




## Acrobat Reader

- **Disable JavaScript in PDF documents**. Acrobat Reader allows to execute JavaScript code from within PDF documents. This is widely abused for exploitation and malicious activity.
### Headline
#### What it does:
<description>

#### Test:
<test steps>

**Expected result before hardening:**
<xxx>

**Expected result after hardening:**
<xxx>

- **Disable execution of objects embedded in PDF documents**. Acrobat Reader also allows to execute embedded objects by opening them. This would normally raise a security alert, but given that legitimate uses of this are rare and limited, Hardentools disables this.
### Headline
#### What it does:
<description>

#### Test:
<test steps>

**Expected result before hardening:**
<xxx>

**Expected result after hardening:**
<xxx>

- **Switch on the Protected Mode** (enabled by default in current versions)
### Headline
#### What it does:
<description>

#### Test:
<test steps>

**Expected result before hardening:**
<xxx>

**Expected result after hardening:**
<xxx>


- **Switch on Protected View** for all files from untrusted sources
### Headline
#### What it does:
<description>

#### Test:
<test steps>

**Expected result before hardening:**
<xxx>

**Expected result after hardening:**
<xxx>


- **Switch on Enhanced Security** (enabled by default in current versions)
### Headline
#### What it does:
<description>

#### Test:
<test steps>

**Expected result before hardening:**
<xxx>

**Expected result after hardening:**
<xxx>


## Test Restore
### Headline
#### What it does:
<description>

#### Test:
<test steps>

**Expected result before hardening:**
<xxx>

**Expected result after hardening:**
<xxx>

TODO: also test partial harden and restore (and that multiple times)