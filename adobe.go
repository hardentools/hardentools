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

var adobe_versions = []string{
	"DC", // Acrobat Reader DC
	"XI", // Acrobat Reader XI
}

// methods used by trigger_* methods for writing the actual registry key values
func harden_adobe(pathRegEx string, value_name string, value uint32) {
	for _, adobe_version := range adobe_versions {
		path := fmt.Sprintf(pathRegEx, adobe_version)
		key, _, _ := registry.CreateKey(registry.CURRENT_USER, path, registry.ALL_ACCESS)
		// save current state
		save_original_registry_DWORD(key, path, value_name)
		// harden
		key.SetDWordValue(value_name, value)
		key.Close()
	}
}

func restore_adobe(pathRegEx string, value_name string) {
	for _, adobe_version := range adobe_versions {
		path := fmt.Sprintf(pathRegEx, adobe_version)
		key, _ := registry.OpenKey(registry.CURRENT_USER, path, registry.ALL_ACCESS)
		// restore previous state
		restore_key(key, path, value_name)
		key.Close()
	}
}

/*
bEnableJS possible values:
0 - Disable AcroJS
1 - Enable AcroJS
*/

func trigger_pdf_js(harden bool) {
	var value uint32
	var value_name = "bEnableJS"
	var pathRegEx = "SOFTWARE\\Adobe\\Acrobat Reader\\%s\\JSPrefs"

	if harden == false {
		events.AppendText("Restoring original settings for Acrobat Reader JavaScript\n")
		restore_adobe(pathRegEx, value_name)
	} else {
		events.AppendText("Hardening by disabling Acrobat Reader JavaScript\n")
		value = 0 // Disable AcroJS
		harden_adobe(pathRegEx, value_name, value)
	}
}

/*
bAllowOpenFile set to 0 and
bSecureOpenFile set to 1 to disable
the opening of non-PDF documents
*/

func trigger_pdf_objects(harden bool) {
	var allow_value uint32
	var secure_value uint32
	var value_name_allow = "bAllowOpenFile"
	var value_name_secure = "bSecureOpenFile"
	var pathRegEx = "SOFTWARE\\Adobe\\Acrobat Reader\\%s\\Originals"

	if harden == false {
		events.AppendText("Restoring original settings for embedded objects in PDFs\n")
		restore_adobe(pathRegEx, value_name_allow)
		restore_adobe(pathRegEx, value_name_secure)
	} else {
		events.AppendText("Hardening by disabling embedded objects in PDFs\n")
		allow_value = 0
		secure_value = 1
		harden_adobe(pathRegEx, value_name_allow, allow_value)
		harden_adobe(pathRegEx, value_name_secure, secure_value)
	}
}
