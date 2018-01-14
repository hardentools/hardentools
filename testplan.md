![Hardentools](https://github.com/securitywithoutborders/hardentools/raw/master/graphics/icon%40128.png)

# Hardentools Test Plan v0.1

## Generic Windows Features

### Disable Windows Script Host
#### What it does:
Windows Script Host allows the execution of VBScript and Javascript files on Windows operating systems. This is very commonly used by regular malware (such as ransomware) as well as targeted malware.

#### Test:
Create .js and .vbs file with some arbitrary text (or valid code) and try to execute them.

**Expected result before hardening:**
Script is executed or runtime error due to malformed script is shown

**Expected result after hardening:**
There should appear a "Windows Script Host" dialog that says that WSH is deactivated.

### Disabling AutoRun and AutoPlay
#### What it does:
Disables AutoRun / AutoPlay for all devices. For example, this should prevent applicatons from automatically executing when you plug a USB stick into your computer.

#### Test AutoRun:
Create autorun.inf on USB Stick that executes a arbitrary executable on the stick. Plug in USB Stick.

**Expected result before hardening:**
Depending on the Windows version nothing happens (AutoRun is disabled by default)
or the executable is started or the executable is an option in the AutoPlay dialog (see below)

**Expected result after hardening:**
No dialog appears, no explorer windows opens, no executable starts.
The stick can only be accessed by opening it manuallys.

#### Test AutoPlay:
Plugin an USB Stick that has no autorun.inf in the base directory.

**Expected result before hardening:**
An AutoPlay windows is opened automatically that asks the user what he wants to do (open explorer, import pictures, ...). Depending on the settings also an explorer windows might appear automatically (without AutoPLay window)

**Expected result after hardening:**
No dialog appears, no explorer windows opens.
The stick can only be accessed by opening it manuallys.

### Disables powershell.exe, powershell_ise.exe and cmd.exe execution via Windows Explorer
#### What it does:
You will not be able to use the terminal by starting cmd.exe and it should prevent the use of PowerShell by malicious code trying to infect the system.

#### Test:
Open every one of the following executables from explorer or Windows Start Menu:
- powershell.exe (32 and 64 bit versions if available)
- powershell_ise.exe (32 and 64 bit versions if available)
- cmd.exe

**Expected result before hardening:**
Executables starts

**Expected result after hardening:**
Nothing happens (windows doesn't react on mouse click) or displays error message


### Disable file extensions mainly used for malicious purposes
#### What it does:
Disables the ".hta", ".js", ".JSE", ".WSH", ".WSF", ".scf", ".scr", ".vbs", ".vbe" and ".pif" file extensions for the current user (and for system wide defaults, which is only relevant for newly created users).

#### Test:
Create a file for every extension mentioned above (empty text file is sufficient)

**Expected result before hardening:**
The file is shown in explorer with the appropriate icon for its extension. Upon starting the file, it is tried to open the file (corresponding error message is shown if it is not of the appropriate file type).

**Expected result after hardening:**
The file is shown in explorer with only the empty icon for unknown file types. Upon starting the file a dialog is presented which program to use.


### TODO from here on

- **Sets User Account Control (UAC) to always ask for permission** (even on configuration changes only) and to use "secure desktop".


- **Shows file extensions and hidden files in explorer**.

- **Windows Defender Attack Surface Reduction (ASR)**. Enables varios remediations using ASR starting with Windows 10 / 1709 (Block executable content from email client and webmail, Block Office applications from creating child processes, Block Office applications from creating executable content & from injecting code into other processes, Block JavaScript or VBScript from launching downloaded executable content, Block execution of potentially obfuscated scripts, Block Win32 API calls from Office macro)

## Microsoft Office

- **Disable Macros**. Macros are at times used by Microsoft Office users to script and automate certain activities, especially calculations with Microsoft Excel. However, macros are currently a security plague, and they are widely used as a vehicle for compromise. With Hardentools, macros are disabled and the "Enable this Content" notification is disabled too, to prevent users from being tricked.

- **Disable OLE object execution**. Microsoft Office applications are able to embed so called "OLE objects" and execute them, at times also automatically (for example through PowerPoint animations). Windows executables, such as spyware, can also be embedded and executed as an object. This is also a security disaster which we observed used time and time again, particularly in attacks against activists in repressed regions. Hardentools entirely disables this functionality.

- **Disabling ActiveX**. Disables ActiveX Controls for all Office applications.

- **Disable DDE**. Disables DDE for Word and Excel

## Acrobat Reader

- **Disable JavaScript in PDF documents**. Acrobat Reader allows to execute JavaScript code from within PDF documents. This is widely abused for exploitation and malicious activity.

- **Disable execution of objects embedded in PDF documents**. Acrobat Reader also allows to execute embedded objects by opening them. This would normally raise a security alert, but given that legitimate uses of this are rare and limited, Hardentools disables this.

- **Switch on the Protected Mode** (enabled by default in current versions)

- **Switch on Protected View** for all files from untrusted sources

- **Switch on Enhanced Security** (enabled by default in current versions)

## Test Restore

TODO: also test partial harden and restore (and that multiple times)