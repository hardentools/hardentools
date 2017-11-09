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
)

var officeVersions = []string{
	"12.0", // Office 2007
	"14.0", // Office 2010
	"15.0", // Office 2013
	"16.0", // Office 2016
}

var standardOfficeApps = []string{"Excel", "PowerPoint", "Word"}

func _hardenOffice(pathRegEx string, valueName string, value uint32, officeApps []string) {
	for _, officeVersion := range officeVersions {
		for _, officeApp := range officeApps {
			path := fmt.Sprintf(pathRegEx, officeVersion, officeApp)
			key, _ := registry.OpenKey(registry.CURRENT_USER, path, registry.ALL_ACCESS)
			// Save current state.
			saveOriginalRegistryDWORD(key, path, valueName)
			// Harden.
			key.SetDWordValue(valueName, value)
			key.Close()
		}
	}
}

func _restoreOffice(pathRegEx string, valueName string, officeApps []string) {
	for _, officeVersion := range officeVersions {
		for _, officeApp := range officeApps {
			path := fmt.Sprintf(pathRegEx, officeVersion, officeApp)
			key, _ := registry.OpenKey(registry.CURRENT_USER, path, registry.ALL_ACCESS)
			// restore previous state
			restoreKey(key, path, valueName)
			key.Close()
		}
	}
}

// Office Packager Objects

// 0 - No prompt from Office when user clicks, object executes
// 1 - Prompt from Office when user clicks, object executes
// 2 - No prompt, Object does not execute

func triggerOfficeOLE(harden bool) {
	var valueName = "PackagerPrompt"
	var pathRegEx = "SOFTWARE\\Microsoft\\Office\\%s\\%s\\Security"

	if harden == false {
		events.AppendText("Restoring original settings for Office Packager Objects\n")

		_restoreOffice(pathRegEx, valueName, standardOfficeApps)
	} else {
		events.AppendText("Hardening by disabling Office Packager Objects\n")
		var value uint32 = 2

		_hardenOffice(pathRegEx, valueName, value, standardOfficeApps)
	}
}

// Office Macros

// 1 - Enable all
// 2 - Disable with notification
// 3 - Digitally signed only
// 4 - Disable all

func triggerOfficeMacros(harden bool) {
	var value uint32
	var valueName = "VBAWarnings"
	var pathRegEx = "SOFTWARE\\Microsoft\\Office\\%s\\%s\\Security"

	if harden == true {
		events.AppendText("Hardening by disabling Office Macros\n")
		value = 4

		_hardenOffice(pathRegEx, valueName, value, standardOfficeApps)
	} else {
		events.AppendText("Restoring original settings for Office Macros\n")

		_restoreOffice(pathRegEx, valueName, standardOfficeApps)
	}
}

// ActiveX

func triggerOfficeActiveX(harden bool) {
	var path = "SOFTWARE\\Microsoft\\Office\\Common\\Security"
	key, _, _ := registry.CreateKey(registry.CURRENT_USER, path, registry.WRITE)
	var valueName = "DisableAllActiveX"

	if harden == false {
		events.AppendText("Restoring original settings for ActiveX in Office\n")
		// Retrieve saved state.
		value, err := retrieveOriginalRegistryDWORD(path, valueName)
		if err == nil {
			key.SetDWordValue(valueName, value)
		} else {
			key.DeleteValue(valueName)
		}
	} else {
		events.AppendText("Hardening by disabling ActiveX in Office\n")
		// Save current state.
		saveOriginalRegistryDWORD(key, path, valueName)
		// Harden.
		key.SetDWordValue(valueName, 1)
	}

	key.Close()
}

// DDE Mitigations for Word and Excel
// doesnt harden OneNote for now (due to high impact)
// [HKEY_CURRENT_USER\Software\Microsoft\Office\%s\Word\Options]
// [HKEY_CURRENT_USER\Software\Microsoft\Office\%s\Word\Options\WordMail]
// [HKEY_CURRENT_USER\Software\Microsoft\Office\%s\Excel\Options]
//    "DontUpdateLinks"=dword:00000001
// additionally only for Excel:
// [HKEY_CURRENT_USER\Software\Microsoft\Office\%s\Excel\Options]
//   "DDEAllowed"=dword:00000000
//   "DDECleaned"=dword:00000001
//   "Options"=dword:00000117
func triggerOfficeDDE(harden bool) {
	var valueName_links = "DontUpdateLinks"
	var value_links uint32 = 1

	var valueName_DDEAllowed = "DDEAllowed"
	var value_DDEAllowed uint32 = 0

	var valueName_DDECleaned = "DDECleaned"
	var value_DDECleaned uint32 = 1

	var valueName_Options = "Options"
	var value_Options uint32 = 0x117 // dword:00000117

	var pathRegEx = "SOFTWARE\\Microsoft\\Office\\%s\\%s\\Options"
	var pathRegExWordMail = "SOFTWARE\\Microsoft\\Office\\%s\\%s\\Options\\WordMail"

	if harden == false {
		events.AppendText("Restoring original settings for Office DDE Links\n")

		_restoreOffice(pathRegEx, valueName_links, []string{"Word", "Excel"})
		_restoreOffice(pathRegExWordMail, valueName_links, []string{"Word"})
		_restoreOffice(pathRegEx, valueName_Options, []string{"Excel"})
		_restoreOffice(pathRegEx, valueName_DDECleaned, []string{"Excel"})
		_restoreOffice(pathRegEx, valueName_DDEAllowed, []string{"Excel"})
	} else {
		events.AppendText("Hardening by disabling Office DDE Links\n")

		_hardenOffice(pathRegEx, valueName_links, value_links, []string{"Word", "Excel"})
		_hardenOffice(pathRegExWordMail, valueName_links, value_links, []string{"Word"})
		_hardenOffice(pathRegEx, valueName_DDEAllowed, value_DDEAllowed, []string{"Excel"})
		_hardenOffice(pathRegEx, valueName_DDECleaned, value_DDECleaned, []string{"Excel"})
		_hardenOffice(pathRegEx, valueName_Options, value_Options, []string{"Excel"})
	}
}
