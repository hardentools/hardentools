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

// What better not to disable:
// - .bat/.cmd (most probably breaks many programs; but would also prevent arbitrary code (including cmd.exe and powershell.exe) to be executed, even if disabled using Explorer\DisallowRun)
// -
// What to disable:
// - .hta allows execution of JavaScript and other scripting languages; seldomly run by user directly)
// - .js allows execution of JavaScript
// - .jse JScript Encoded Script File
// - .WSF Windows Script files
// - .WSH Windows Script Host files
// - .scf Windows Explorer Shell Cmd File (mainly used for "Show Desktop" button)
// - .scr Windows Screen Saver extension, may break these, but seen commonly in phishing emails, contains executable code
// - .vbs Visual Basic Script, mainly malicious
// - .VBE Visual Basic Script Encoded, mainly malicious
// - .pif Normally, a PIF file contains information that defines how an MS-DOS-based program should run. Windows analyzes PIF files with the ShellExecute function and may run them as executable programs. Therefore, a PIF file can be used to transmit viruses or other harmful scripts.

type Extension struct {
	ext   string
	assoc string
}

type ExplorerAssociations struct {
	extensions []Extension
	shortName  string
}

var FileAssociations = ExplorerAssociations{
	extensions: []Extension{
		{".hta", "htafile"},
		{".js", "JSFile"},
		{".JSE", "JSEFile"},
		{".WSH", "WSHFile"},
		{".WSF", "WSFFile"},
		{".scf", "SHCmdFile"},
		{".scr", "scrfile"},
		{".vbs", "VBSFile"},
		{".VBE", "VBEFile"},
		{".pif", "piffile"}},
	shortName: "FileAssociations",
}

func (explAssoc ExplorerAssociations) harden(harden bool) {
	if harden == false {
		//events.AppendText("Restoring default settings by enabling potentially malicious file associations\n")

		for _, extension := range explAssoc.extensions {
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
		//events.AppendText("Hardening by disabling potentially malicious file associations\n")

		for _, extension := range explAssoc.extensions {
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
			valueNames, _ := regKey.ReadValueNames(100) // just used "100" because there shouldn't be more entries (default is one entry)
			for _, valueName := range valueNames {
				regKey.DeleteValue(valueName)
			}
			regKey.Close()
		}
	}
}

func (explAssoc ExplorerAssociations) isHardened() (isHardened bool) {
	var hardened = true

	for _, extension := range explAssoc.extensions {
		regKeyString := fmt.Sprintf("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\FileExts\\%s\\OpenWithProgids", extension.ext)
		regKey, _ := registry.OpenKey(registry.CURRENT_USER, regKeyString, registry.READ)

		// Step 1: Check association (system wide default)
		assocString := fmt.Sprintf("assoc %s", extension.ext)
		_, err := exec.Command("cmd.exe", "/E:ON", "/C", assocString).Output()
		if err != nil {
			//events.AppendText(extension.ext)
			//events.AppendText(" seems to be hardened\n")
		} else {
			hardened = false
			//events.AppendText(extension.ext)
			//events.AppendText(fmt.Sprintln(" seems not to be hardened: %s\n", out))
		}

		// Step 2: Check user association
		valueNames, _ := regKey.ReadValueNames(100) // just used "100" because there shouldn't be more entries (default is one entry)
		if len(valueNames) > 0 {
			hardened = false
			//events.AppendText(extension.ext)
			//events.AppendText(" seems NOT to be hardened\n")
		}

		regKey.Close()
	}

	return hardened
}

func (explAssoc ExplorerAssociations) name() string {
	return explAssoc.shortName
}
