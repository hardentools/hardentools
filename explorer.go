// Hardentools
// Copyright (C) 2017  Security Without Borders
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package main

import (
	"fmt"
	"golang.org/x/sys/windows/registry"
	"os/exec"
)

// Documentation:
// What better not to disable:
// - .bat/.cmd (most probably breaks many programs; but would also prevent arbitrary code (including cmd.exe and powershell.exe) to be executed, even if disabled using Explorer\DisallowRun)
// -
// What to disable:
// - .hta allows execution of JavaScript and other scripting languages; seldomly run by user directly)
// - .js allows execution of JavaScript
// - .jse JScript Encoded Script File
// - .WSF Windows Script files
// - .WSH Windows Script Host files
// - .scr Windows Screen Saver extension, may break these, but seen commonly in phishing emails, contains executable code
// - .vbs Visual Basic Script, mainly malicious
// - .pif Normally, a PIF file contains information that defines how an MS-DOS-based program should run. Windows analyzes PIF files with the ShellExecute function and may run them as executable programs. Therefore, a PIF file can be used to transmit viruses or other harmful scripts.
func trigger_fileassoc(harden bool) {
	type Extension struct {
		ext string
		assoc string
	}
	var extensions = [8]Extension {
		{ ".hta", "htafile" },
		{ ".js", "JSFile" },
		{ ".JSE", "JSEFile" },
		{ ".WSH", "WSHFile" },
		{ ".WSF", "WSFFile" },
		{ ".scr", "scrfile" },
		{ ".vbs", "VBSFile" },
		{ ".pif", "piffile" },
	}

	if harden==false {
		events.AppendText("Restoring default settings by enabling potentially malicious file associations\n")
		
		for _, extension := range extensions {
			// Step 1: Reassociate system wide default
			assocString := fmt.Sprintf("assoc %s=%s", extension.ext, extension.assoc)
			_, err := exec.Command("cmd.exe", "/E:ON", "/C", assocString).Output()
			if err != nil {
				events.AppendText("error occured")
				events.AppendText(fmt.Sprintln("%s", err))
			}
			
			// Step 2 (Reassociate user defaults) is not necessary, since this is automatically done by Windows on first usage
		}
	} else {
		events.AppendText("Hardening by disabling potentially malicious file associations\n")
		
		for _, extension := range extensions {
			regKeyString := fmt.Sprintf("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\FileExts\\%s\\OpenWithProgids", extension.ext)
			regKey, _ := registry.OpenKey(registry.CURRENT_USER, regKeyString, registry.ALL_ACCESS)
			
			// Step 1: Remove association (system wide default)
			assocString := fmt.Sprintf("assoc %s=", extension.ext)
			_, err := exec.Command("cmd.exe", "/E:ON", "/C", assocString).Output()
			if err != nil {
				events.AppendText("error occured")
				events.AppendText(fmt.Sprintln("%s", err))
			}
			// Step 2: Remove user association
			value_names, _ := regKey.ReadValueNames(100) // just used "100" because there shouldn't be more entries (default is one entry)
			for _, value_name := range value_names {
				regKey.DeleteValue(value_name)
			}
			regKey.Close()
		}
	}
}
