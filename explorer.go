// Hardentools
// Copyright (C) 2017-2020 Security Without Borders
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
)

// What better not to disable:
// - .bat/.cmd (most probably breaks many programs; but would also prevent
//    arbitrary code (including cmd.exe and powershell.exe) to be executed,
//    even if disabled using Explorer\DisallowRun).
//
// What to disable:
// - .hta allows execution of JavaScript and other scripting languages;
//   seldom run by user directly).
// - .js allows execution of JavaScript.
// - .jse JScript Encoded Script File.
// - .WSF Windows Script files.
// - .WSH Windows Script Host files.
// - .scf Windows Explorer Shell Cmd File (mainly used for "Show Desktop" button).
// - .scr Windows Screen Saver extension, may break these, but seen commonly in
//   phishing emails, contains executable code.
// - .vbs Visual Basic Script, mainly malicious.
// - .VBE Visual Basic Script Encoded, mainly malicious.
// - .pif Normally, a PIF file contains information that defines how an
//   MS-DOS-based program should run.
//   Windows analyzes PIF files with the ShellExecute function and may run them
//   as executable programs. Therefore, a PIF file can be used to transmit
//   viruses or other harmful scripts.
// - .mht Due to unpatched IE bug (https://www.zdnet.com/article/internet-explorer-zero-day-lets-hackers-steal-files-from-windows-pcs/).

// Extension is a helper struct.
type Extension struct {
	ext   string
	assoc string
}

// ExplorerAssociations is the struct for HardenInterface implementation.
type ExplorerAssociations struct {
	extensions      []Extension
	shortName       string
	longName        string
	description     string
	hardenByDefault bool
}

// FileAssociations contains all extensions to be removed.
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
		{".pif", "piffile"},
		{".mht", "mhtmlfile"},
	},
	shortName:       "File Associations",
	longName:        "File associations",
	hardenByDefault: true,
}

// Harden explorer associations.
func (explAssoc ExplorerAssociations) Harden(harden bool) error {
	if harden == false {
		// Restore.
		var lastError error

		for _, extension := range explAssoc.extensions {
			// Step 1: Reassociate system wide default.
			// TODO: only reassoc extensions that were also there before hardening
			assocString := fmt.Sprintf("assoc %s=%s", extension.ext, extension.assoc)
			_, err := executeCommand("cmd.exe", "/E:ON", "/C", assocString)
			if err != nil {
				Trace.Println("Error during reassociation of file extension " + extension.ext + ": " + err.Error())
				lastError = err
			}

			// Step 2 (Reassociate user defaults) is not necessary,
			// since this is automatically done by Windows on first usage.
		}

		if lastError != nil {
			// NOTE: just return nil for now, since errors are quite normal.
			return nil
			//return lastError
		}
	} else {
		// Harden.
		for _, extension := range explAssoc.extensions {
			var openWithProgidsDoesNotExist = false
			regKeyString := fmt.Sprintf("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\FileExts\\%s\\OpenWithProgids", extension.ext)
			regKey, err := registry.OpenKey(registry.CURRENT_USER, regKeyString, registry.ALL_ACCESS)
			if err != nil {
				Trace.Println("Could not open: CURRENT_USER\\", regKeyString)

				// Do not return an error, because it seems to be quite common
				// that this does not exist for different extensions;
				// just remember this for later.
				openWithProgidsDoesNotExist = true
			}
			defer regKey.Close()

			// Step 1: Remove association (system wide default).
			assocString := fmt.Sprintf("assoc %s=", extension.ext)
			_, err2 := executeCommand("cmd.exe", "/E:ON", "/C", assocString)
			if err2 != nil {
				Info.Println("Executing ", assocString, " failed")
				return err2
			}

			// Step 2: Remove user association.
			if !openWithProgidsDoesNotExist {
				// Only used "100" because there shouldn't be more entries (default is one entry).
				valueNames, _ := regKey.ReadValueNames(100)
				for _, valueName := range valueNames {
					err3 := regKey.DeleteValue(valueName)
					if err3 != nil {
						Info.Println("Removing user association ", valueName, " failed")
						return err3
					}
				}
			}
		}
	}
	return nil
}

// IsHardened returns true, even if only one extension is hardened (to prevent
// restore from not being executed), due to errors in hardening quite common.
func (explAssoc ExplorerAssociations) IsHardened() (isHardened bool) {
	var hardened = false

	for _, extension := range explAssoc.extensions {
		// Check only system wide association (system wide default), since
		// user settings are restored automatically when user first opens such
		// a file.
		assocString := fmt.Sprintf("assoc %s", extension.ext)
		out, err := executeCommand("cmd.exe", "/E:ON", "/C", assocString)
		if err != nil {
			Trace.Printf("isHardened?: (ok) %s (output = %s)(error=%s)", assocString, string(out[:]), err.Error())
			hardened = true
		} else {
			Trace.Printf("isHardened?: (not) %s (output = %s)", assocString, string(out[:]))
		}
	}

	return hardened
}

// Name returns the (short) name of the harden item.
func (explAssoc ExplorerAssociations) Name() string {
	return explAssoc.shortName
}

// LongName returns the long name of the harden item.
func (explAssoc ExplorerAssociations) LongName() string {
	return explAssoc.longName
}

// Description of the harden item.
func (explAssoc ExplorerAssociations) Description() string {
	return explAssoc.description
}

// HardenByDefault returns if subject should be hardened by default.
func (explAssoc ExplorerAssociations) HardenByDefault() bool {
	return explAssoc.hardenByDefault
}
