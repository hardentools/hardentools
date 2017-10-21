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

var officeApps = []string{"Excel", "PowerPoint", "Word"}

func _hardenOffice(pathRegEx string, valueName string, value uint32) {
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

func _restoreOffice(pathRegEx string, valueName string) {
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

		_restoreOffice(pathRegEx, valueName)
	} else {
		events.AppendText("Hardening by disabling Office Packager Objects\n")
		var value uint32 = 2

		_hardenOffice(pathRegEx, valueName, value)
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

		_hardenOffice(pathRegEx, valueName, value)
	} else {
		events.AppendText("Restoring original settings for Office Macros\n")

		_restoreOffice(pathRegEx, valueName)
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
