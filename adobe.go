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

var adobeVersions = []string{
	"DC", // Acrobat Reader DC
	"XI", // Acrobat Reader XI
}

func _hardenAdobe(pathRegEx string, valueName string, value uint32) {
	for _, adobeVersion := range adobeVersions {
		path := fmt.Sprintf(pathRegEx, adobeVersion)
		key, _, _ := registry.CreateKey(registry.CURRENT_USER, path, registry.ALL_ACCESS)

		saveOriginalRegistryDWORD(key, path, valueName)

		key.SetDWordValue(valueName, value)
		key.Close()
	}
}

func _restoreAdobe(pathRegEx string, valueName string) {
	for _, adobeVersion := range adobeVersions {
		path := fmt.Sprintf(pathRegEx, adobeVersion)
		key, _ := registry.OpenKey(registry.CURRENT_USER, path, registry.ALL_ACCESS)

		restoreKey(key, path, value_name)
		key.Close()
	}
}

// bEnableJS possible values:
// 0 - Disable AcroJS
// 1 - Enable AcroJS

func triggerPDFJS(harden bool) {
	var value uint32
	var valueName = "bEnableJS"
	var pathRegEx = "SOFTWARE\\Adobe\\Acrobat Reader\\%s\\JSPrefs"

	if harden == false {
		events.AppendText("Restoring original settings for Acrobat Reader JavaScript\n")
		_restoreAdobe(pathRegEx, valueName)
	} else {
		events.AppendText("Hardening by disabling Acrobat Reader JavaScript\n")
		value = 0 // Disable AcroJS
		_hardenAdobe(pathRegEx, valueName, value)
	}
}

// bAllowOpenFile set to 0 and
// bSecureOpenFile set to 1 to disable
// the opening of non-PDF documents

func triggerPDFObjects(harden bool) {
	var allowValue uint32
	var secureValue uint32
	var allowValueName = "bAllowOpenFile"
	var secureValueName = "bSecureOpenFile"
	var pathRegEx = "SOFTWARE\\Adobe\\Acrobat Reader\\%s\\Originals"

	if harden == false {
		events.AppendText("Restoring original settings for embedded objects in PDFs\n")
		_restoreAdobe(pathRegEx, allowValueName)
		_restoreAdobe(pathRegEx, secureValueName)
	} else {
		events.AppendText("Hardening by disabling embedded objects in PDFs\n")
		allowValue = 0
		secureValue = 1
		_hardenAdobe(pathRegEx, allowValueName, allowValue)
		_hardenAdobe(pathRegEx, secureValueName, secureValue)
	}
}

// Switch on the Protected Mode setting under "Security (Enhanced)" (enabled by default in current versions)
// (HKEY_LOCAL_USER\Software\Adobe\Acrobat Reader<version>\Privileged -> DWORD „bProtectedMode“)
// 0 - Disable Protected Mode
// 1 - Enable Protected Mode

func triggerPDFProtectedMode(harden bool) {
	var value uint32
	var valueName = "bProtectedMode"
	var pathRegEx = "SOFTWARE\\Adobe\\Acrobat Reader\\%s\\Privileged"

	if harden == false {
		events.AppendText("Restoring original settings for Acrobat Reader Protected Mode\n")
		_restoreAdobe(pathRegEx, valueName)
	} else {
		events.AppendText("Hardening by enabling Acrobat Reader Protected Mode\n")
		value = 1
		_hardenAdobe(pathRegEx, valueName, value)
	}
}

// Switch on Protected View for all files from untrusted sources
// (HKEY_CURRENT_USER\SOFTWARE\Adobe\Acrobat Reader\<version>\TrustManager -> iProtectedView)
// 0 - Disable Protected View
// 1 - Enable Protected View

func triggerPDFProtectedView(harden bool) {
	var value uint32
	var valueName = "iProtectedView"
	var pathRegEx = "SOFTWARE\\Adobe\\Acrobat Reader\\%s\\TrustManager"

	if harden == false {
		events.AppendText("Restoring original settings for Acrobat Reader Protected View\n")
		_restoreAdobe(pathRegEx, valueName)
	} else {
		events.AppendText("Hardening by enabling Acrobat Reader Protected View\n")
		value = 1
		_hardenAdobe(pathRegEx, valueName, value)
	}
}

// Switch on Enhanced Security setting under "Security (Enhanced)"
// (enabled by default in current versions)
// (HKEY_CURRENT_USER\SOFTWARE\Adobe\Acrobat Reader\DC\TrustManager -> bEnhancedSecurityInBrowser = 1 & bEnhancedSecurityStandalone = 1)

func triggerPDFEnhancedSecurity(harden bool) {
	var value uint32
	var valueName = "bEnhancedSecurityInBrowser"
	var valueName2 = "bEnhancedSecurityStandalone"
	var pathRegEx = "SOFTWARE\\Adobe\\Acrobat Reader\\%s\\TrustManager"

	if harden == false {
		events.AppendText("Restoring original settings for Acrobat Reader Enhanced Security\n")
		_restoreAdobe(pathRegEx, valueName)
		_restoreAdobe(pathRegEx, valueName2)
	} else {
		events.AppendText("Hardening by enabling Acrobat Reader Enhanced Security\n")
		value = 1
		_hardenAdobe(pathRegEx, valueName, value)
		_hardenAdobe(pathRegEx, valueName2, value)
	}
}
