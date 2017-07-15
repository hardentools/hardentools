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

var office_versions = []string{
	"12.0", // Office 2007
	"14.0", // Office 2010
	"15.0", // Office 2013
	"16.0", // Office 2016
}

var office_apps = []string{"Excel", "PowerPoint", "Word"}

// methods used by trigger_ole and trigger_macro
func harden_office(pathRegEx string, value_name string, value uint32) {
	for _, office_version := range office_versions {
		for _, office_app := range office_apps {
			path := fmt.Sprintf(pathRegEx, office_version, office_app)
			key, _ := registry.OpenKey(registry.CURRENT_USER, path, registry.ALL_ACCESS)
			// save current state
			save_original_registry_DWORD(key, path, value_name)
			// harden
			key.SetDWordValue(value_name, value)
			key.Close()
		}
	}
}

func restore_office(pathRegEx string, value_name string) {
	for _, office_version := range office_versions {
		for _, office_app := range office_apps {
			path := fmt.Sprintf(pathRegEx, office_version, office_app)
			key, _ := registry.OpenKey(registry.CURRENT_USER, path, registry.ALL_ACCESS)
			// restore previous state
			restore_key(key, path, value_name)
			key.Close()
		}
	}
}

// Office Packager Objects

/*
0 - No prompt from Office when user clicks, object executes
1 - Prompt from Office when user clicks, object executes
2 - No prompt, Object does not execute
*/

func trigger_ole(harden bool) {
	var value_name = "PackagerPrompt"
	var pathRegEx = "SOFTWARE\\Microsoft\\Office\\%s\\%s\\Security"

	if harden == false {
		events.AppendText("Restoring original settings for Office Packager Objects\n")

		restore_office(pathRegEx, value_name)
	} else {
		events.AppendText("Hardening by disabling Office Packager Objects\n")
		var value uint32 = 2

		harden_office(pathRegEx, value_name, value)
	}
}

// Office Macros

/*
1 - Enable all
2 - Disable with notification
3 - Digitally signed only
4 - Disable all
*/

func trigger_macro(harden bool) {
	var value uint32
	var value_name = "VBAWarnings"
	var pathRegEx = "SOFTWARE\\Microsoft\\Office\\%s\\%s\\Security"

	if harden == true {
		events.AppendText("Hardening by disabling Office Macros\n")
		value = 4

		harden_office(pathRegEx, value_name, value)
	} else {
		events.AppendText("Restoring original settings for Office Macros\n")

		restore_office(pathRegEx, value_name)
	}
}

// ActiveX

func trigger_activex(harden bool) {
	var path = "SOFTWARE\\Microsoft\\Office\\Common\\Security"
	key, _, _ := registry.CreateKey(registry.CURRENT_USER, path, registry.WRITE)
	var value_name = "DisableAllActiveX"

	if harden == false {
		events.AppendText("Restoring original settings for ActiveX in Office\n")
		// retrieve saved state
		value, err := retrieve_original_registry_DWORD(path, value_name)
		if err == nil {
			key.SetDWordValue(value_name, value)
		} else {
			key.DeleteValue(value_name)
		}
	} else {
		events.AppendText("Hardening by disabling ActiveX in Office\n")
		// save current state
		save_original_registry_DWORD(key, path, value_name)
		// harden
		key.SetDWordValue(value_name, 1)
	}
	key.Close()
}
