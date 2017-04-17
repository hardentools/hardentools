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
	"XI", // Acrobat Reader XI - To test
}

/*
bEnableJS possible values:
0 - Disable AcroJS
1 - Enable AcroJS
*/

func trigger_pdf_js(harden bool) {
	var value uint32

	if harden==false {
		events.AppendText("Restoring default by enabling Acrobat Reader JavaScript\n")
		value = 1
	} else {
		events.AppendText("Hardening by disabling Acrobat Reader JavaScript\n")
		value = 0
	}

	for _, adobe_version := range adobe_versions {
		path := fmt.Sprintf("SOFTWARE\\Adobe\\Acrobat Reader\\%s\\JSPrefs", adobe_version)
		key, _, _ := registry.CreateKey(registry.CURRENT_USER, path, registry.WRITE)

		key.SetDWordValue("bEnableJS", value)
		key.Close()
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

	if harden==false {
		events.AppendText("Restoring default by enabling embedded objects in PDFs\n")
		allow_value = 1
		secure_value = 0
	} else {
		events.AppendText("Hardening by disabling embedded objects in PDFs\n")
		allow_value = 0
		secure_value = 1
	}

	for _, adobe_version := range adobe_versions {
		path := fmt.Sprintf("SOFTWARE\\Adobe\\Acrobat Reader\\%s\\Originals", adobe_version)
		key, _, _ := registry.CreateKey(registry.CURRENT_USER, path, registry.WRITE)
		
		key.SetDWordValue("bAllowOpenFile", allow_value)
		key.SetDWordValue("bSecureOpenFile", secure_value)
		key.Close()
	}
}
