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
			key, _, _ := registry.CreateKey(registry.CURRENT_USER, path, registry.ALL_ACCESS)
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

// DDE Mitigations for Word, Outlook and Excel
// doesnt harden OneNote for now (due to high impact)
// [HKEY_CURRENT_USER\Software\Microsoft\Office\%s\Word\Options]
// [HKEY_CURRENT_USER\Software\Microsoft\Office\%s\Word\Options\WordMail] (this one is for Outlook)
// [HKEY_CURRENT_USER\Software\Microsoft\Office\%s\Excel\Options]
//    "DontUpdateLinks"=dword:00000001
//
// additionally only for Excel:
// [HKEY_CURRENT_USER\Software\Microsoft\Office\%s\Excel\Options]
//   "DDEAllowed"=dword:00000000
//   "DDECleaned"=dword:00000001
//   "Options"=dword:00000117
// [HKEY_CURRENT_USER\Software\Microsoft\Office\<version>\Excel\Security]
//   WorkbookLinkWarnings(DWORD) = 2
//
// for Word&Outlook 2007:
// [HKEY_CURRENT_USER\Software\Microsoft\Office\12.0\Word\Options\vpref]
//    fNoCalclinksOnopen_90_1(DWORD)=1
func triggerOfficeDDE(harden bool) {
	var valueNameLinks = "DontUpdateLinks"
	var valueLinks uint32 = 1

	var valueNameDDEAllowed = "DDEAllowed"
	var valueDDEAllowed uint32 = 0

	var valueNameDDECleaned = "DDECleaned"
	var valueDDECleaned uint32 = 1

	var valueNameOptions = "Options"
	var valueOptions uint32 = 0x117 // dword:00000117

	var valueNameWorkbookLinkWarnings = "WorkbookLinkWarnings"
	var valueWorkbookLinkWarnings uint32 = 2

	var valueNameWord2007 = "fNoCalclinksOnopen_90_1"
	var valueWord2007 uint32 = 1

	var pathRegEx = "SOFTWARE\\Microsoft\\Office\\%s\\%s\\Options"
	var pathRegExWordMail = "SOFTWARE\\Microsoft\\Office\\%s\\%s\\Options\\WordMail"
	var pathRegExSecurity = "Software\\Microsoft\\Office\\%s\\%s\\Security"
	var pathWord2007 = "Software\\Microsoft\\Office\\12.0\\Word\\Options\\vpref"

	keyWord2007, _, _ := registry.CreateKey(registry.CURRENT_USER, pathWord2007, registry.WRITE)

	if harden == false {
		events.AppendText("Restoring original settings for Office DDE Links\n")

		_restoreOffice(pathRegEx, valueNameLinks, []string{"Word", "Excel"})
		_restoreOffice(pathRegExWordMail, valueNameLinks, []string{"Word"})
		_restoreOffice(pathRegEx, valueNameOptions, []string{"Excel"})
		_restoreOffice(pathRegEx, valueNameDDECleaned, []string{"Excel"})
		_restoreOffice(pathRegEx, valueNameDDEAllowed, []string{"Excel"})
		_restoreOffice(pathRegExSecurity, valueNameWorkbookLinkWarnings, []string{"Excel"})

		//// Word 2007 key:
		// Retrieve saved state.
		value, err := retrieveOriginalRegistryDWORD(pathWord2007, valueNameWord2007)
		if err == nil {
			keyWord2007.SetDWordValue(valueNameWord2007, value)
		} else {
			keyWord2007.DeleteValue(valueNameWord2007)
		}
	} else {
		events.AppendText("Hardening by disabling Office DDE Links\n")

		_hardenOffice(pathRegEx, valueNameLinks, valueLinks, []string{"Word", "Excel"})
		_hardenOffice(pathRegExWordMail, valueNameLinks, valueLinks, []string{"Word"})
		_hardenOffice(pathRegEx, valueNameDDEAllowed, valueDDEAllowed, []string{"Excel"})
		_hardenOffice(pathRegEx, valueNameDDECleaned, valueDDECleaned, []string{"Excel"})
		_hardenOffice(pathRegEx, valueNameOptions, valueOptions, []string{"Excel"})
		_hardenOffice(pathRegExSecurity, valueNameWorkbookLinkWarnings, valueWorkbookLinkWarnings, []string{"Excel"})

		//// Word 2007 key:
		// Save current state.
		saveOriginalRegistryDWORD(keyWord2007, pathWord2007, valueNameWord2007)
		// Harden.
		keyWord2007.SetDWordValue(valueNameWord2007, valueWord2007)

	}
}
