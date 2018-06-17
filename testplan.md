![Hardentools](https://github.com/securitywithoutborders/hardentools/raw/master/graphics/icon%40128.png)

# Hardentools Test Plan v0.1

## Generic Windows Features

### Disable Windows Script Host
#### What it does:
Windows Script Host allows the execution of VBScript and Javascript files on Windows operating systems. This is very commonly used by regular malware (such as ransomware) as well as targeted malware.

#### Test steps:
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

* Depending on the Windows version nothing happens (AutoRun is disabled by default) or the executable is started or the executable is an option in the AutoPlay dialog (see below)

**Expected result after hardening:**

* No dialog appears, no explorer windows opens, no executable starts. The stick can only be accessed by opening it manually.

#### Test AutoPlay:
Plugin an USB Stick that has no autorun.inf in the base directory.

**Expected result before hardening:**

* An AutoPlay window opens automatically that asks the user what he wants to do (open explorer, import pictures, ...). Depending on the settings also an explorer window might appear automatically (without AutoPLay window)

**Expected result after hardening:**

* No dialog appears, no explorer windows opens. The stick can only be accessed by opening it manually.

### Disables powershell.exe, powershell_ise.exe and cmd.exe execution via Windows Explorer
#### What it does:
You will not be able to use the terminal by starting cmd.exe and it should prevent the usage of PowerShell by malicious code trying to infect the system.

#### Test steps:
Open every one of the following executables from explorer or Windows Start Menu:
* powershell.exe (32 and 64 bit versions if available)
* powershell_ise.exe (32 and 64 bit versions if available)
* cmd.exe

**Expected result before hardening:**

* Executables start

**Expected result after hardening:**

* Nothing happens (windows doesn't react on mouse click) or displays error message


### Disable file extensions mainly used for malicious purposes
#### What it does:
Disables the ".hta", ".js", ".JSE", ".WSH", ".WSF", ".scf", ".scr", ".vbs", ".vbe" and ".pif" file extensions for the current user (and for system wide defaults, which is only relevant for newly created users).

#### Test steps:
* Create a file for every extension mentioned above (empty text file is sufficient)

**Expected result before hardening:**

* The file is shown in explorer with the appropriate icon for its extension.
* Upon starting the file, it is tried to open the file (corresponding error message is shown if it is not of the appropriate file type).

**Expected result after hardening:**

* The file is shown in explorer with only the empty icon for unknown file types.
* Upon double clicking the file a dialog is presented which program to use.

### Sets User Account Control (UAC) to always ask for permission
#### What it does:
Sets User Account Control (UAC) to always ask for permission (even on configuration changes only) and to use "secure desktop"

#### Test steps:
* Check UAC (User Account Control) settings in Windows System Settings.
* Open Task Manager

**Expected result before hardening:**

* Opening the UAC settings usually doesn't trigger an UAC dialog and the setting is not on the highest of the four available settings (standard is the second highest)
* Opening the Windows task manager doesn't trigger an UAC dialog

**Expected result after hardening:**

* Opening the UAC settings triggers an UAC dialog and the setting is on the highest setting. During the UAC dialog the desktop is dimmed.
* Opening the Windows task manager does trigger an UAC dialog. During the UAC dialog the desktop is dimmed.

### Shows file extensions and hidden files in explorer
#### What it does:
Shows file extensions and hidden files in explorer

#### Test steps:
Open Windows explorer and verify if file extensions like .txt, .pdf and so on are shown in the filename in explorer

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

#### Test steps:
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

#### Test steps:
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

#### Test steps:
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

#### Test steps:
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

#### Test steps:
* Prepare an Excel and Word document with a DDE code that tries do execute some executable (e.g. calc.exe)
* Open the Excel document and verify if the executable is executed
* Open the Word document and verify if the executable is executed

How to generate malicious DDE documents:
* https://null-byte.wonderhowto.com/how-to/exploit-dde-microsoft-office-defend-against-dde-based-attacks-0180706/

**Expected result before hardening:**

* Executable is executed after user approves with "Yes"

**Expected result after hardening:**

* Executable is not executed; user is not asked anything


## Acrobat Reader

### Disable JavaScript in PDF documents
#### What it does:
Acrobat Reader allows to execute JavaScript code from within PDF documents. This is widely abused for exploitation and malicious activity.

#### Test steps:
* Prepare an PDF document with embedded JavaScript code that tries do does some action (e.g. showing an dialog)
* Open the PDF document with Adobe Acrobat Reader and verify if the executable is executed

**Expected result before hardening:**

* JavaScript is executed

**Expected result after hardening:**

* Javacript is not executed

### Disable execution of objects embedded in PDF documents
#### What it does:
Acrobat Reader also allows to execute embedded objects by opening them. This would normally raise a security alert, but given that legitimate uses of this are rare and limited, Hardentools disables this.

#### Test steps:
* Prepare an PDF document with an embedded object
* Open the PDF document and verify if the embedded object is executed

**Expected result before hardening:**

* Embedded object is executed

**Expected result after hardening:**

* Embedded object is not executed

### Switch on the Protected Mode
#### What it does:
This is enabled by default in current versions. It prevents PDF files to write to
the registry or open executables on the client

#### Test steps:
* Open Adobe Reader and disable Protected Mode (if enabled)
* Harden using Hardentools
* Download PDF file from the Internet
* Open downloaded file on Adobe Reader
* Verify if Protected Mode is enabled for this file

**Expected result before hardening:**
* Protected Mode is disabled

**Expected result after hardening:**
* Protected Mode is enabled


### Switch on Protected View
#### What it does:
Switches on Protected View for all files from untrusted sources

#### Test steps:
* Download PDF file from the Internet
* Open downloaded file on Adobe Reader
* Verify if Protected View is enabled for this file

**Expected result before hardening:**
* Protected View is not enabled

**Expected result after hardening:**
* Protected View is enabled, user can deactivate Protected View manually (via yellow message bar)


### Switch on Enhanced Security
#### What it does:
Switches on Enhanced Security (enabled by default in current versions)


With enhanced security enabled, your application “hardens” itself against risky actions by doing the 
following for any document not specifically trusted: 
* Prevents cross domain access. It forces requests for new content to adhere to a “same-origin” policy; that is, access to web pages and other resources originating from a domain other than your calling document is prohibited. 
* Prohibits script and data injection via an FDF, XFDF, and XDP NOT returned as the result of a post from the PDF.
* Blocks stream access to XObjects such as external images. 
* Stops silent printing to a file or hardware printer. 
* Prevents execution of high privilege JavaScript.

Enhanced Security is specifically designed to let you decide what content to trust and help you selectively 
bypass those restrictions for trusted files, folders, and hosts. These trusted domains--called privileged 
locations--are exempt from enhanced security rules.

#### Test steps:
* Open Adobe Reader and disable enhanced security (if enabled)
* Harden using Hardentools
* Verify if Enhanced Security is enabled

**Expected result before hardening:**

* Enhanced Security is disabled

**Expected result after hardening:**

* Enhanced Security is enabled



## Restore Original Settings
### Complete Harden & Restore
#### What it does:
You can harden all (default) settings with hardentools or just a manual subset. In this
testcase we are testing the restore of the original settings on the system when
doing a complete hardening.

#### Test steps:
* Write down the status of all the settings (see testcases above) before hardening.
* Execute hardentools and harden all settings
* Execute hardentools again and restore settings
* Verify if all settings are reverted to the original settings

**Note:** This does not apply for the following settings, since they are currently always reverted to the default state:
* Windows ASR settings
* Disable file extensions mainly used for malicious purposes


### Partial Harden & Restore
#### What it does:
You can harden all (default) settings with hardentools or just a manual subset. In this
testcase we are testing the restore of the original settings on the system when
doing only a partial hardening.

#### Test steps:
* Write down the status of all the settings (see testcases above) before hardening.
* Execute hardentools and harden a specific subset of settings only
* Execute hardentools again and restore settings
* Verify if all hardened settings are reverted to the original settings
* Verify if only the hardened settings are affected upon restore
* Repeat the above procedure with a different set of settings

**Note:** This does not apply for the following settings, since they are currently always reverted to the default state:
* Windows ASR settings
* Disable file extensions mainly used for malicious purposes
