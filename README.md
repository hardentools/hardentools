# Hardentools

Hardentools is a collection of simple utilities designed to disable a number of "features" exposed by operating systems (Microsoft Windows, for now), and primary consumer applications. These features, commonly thought for Enterprise customers, are generally useless to regular users and rather pose as dangers as they are very commonly abused by attackers to execute malicious code on a victim's computer. For the moment this remains an experimental attempt, nothing more, nothing less.

**WARNING: This is just an experiment, it is not meant for public distribution yet. Also, this tool disables a number of features, including of Microsoft Office, Adobe Reader, and Windows, that might cause malfunctions to certain applications. Use this at your own risk.**


## Disabled Features

### Windows

- **Disable Windows Script Host**. Windows Script Host allows the execution of VBScript and Javascript files on Windows operating systems. This is very commonly used by regular malware (such as ransomware) as well as targeted malware.

### Microsoft Office

- **Disable Macros**. Macros are at times used by Microsoft Office users to script and automate certain activities, especially calculations with Microsoft Excel. However, macros are currently a security plague, and they are widely used as a vehicle for compromise. With Hardentools, macros are disabled and the "Enable this Content" notification is disabled too, to prevent users from being tricked.

- **Disable OLE object execution**. Microsoft Office applications are able to embed so called "OLE objects" and execute them, at times also automatically (for example through PowerPoint animations). Windows executables, such as spyware, can also be embedded and executed as an object. This is also a security disaster which we observed used time and time again, particularly in attacks against activists in repressed regions. Hardentools entirely disables this functionality.

- **Disabling ActiveX**. Disables ActiveX Controls for all Office applications.

### Acrobat Reader

- **Disable JavaScript in PDF documents**. Acrobat Reader allows to execute JavaScript code from within PDF documents. This is widely abused for exploitation and malicious activity.

- **Disable execution of objects embedded in PDF documents**. Acrobat Reader also allows to execute embedded objects by opening them. This would normally raise a security alert, but given that legitimate uses of this are rare and limited, Hardentools disables this.

### Windows Explorer

- **Disabling AutoRun and AutoPlay**. Disables AutoRun / AutoPlay for all devices.

### Powershell and cmd.exe
- ** Disables powershell.exe, powershell_ise.exe and cmd.exe execution via Windows Explorer**. Needs local admin rights. Please be aware if the normal user doesn't have local admin rights and you start hardentools.exe with another user (having local admin rights), the settings will only work for this admin user.
