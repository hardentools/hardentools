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

var standardOfficeVersions = []string{
	"12.0", // Office 2007
	"14.0", // Office 2010
	"15.0", // Office 2013
	"16.0", // Office 2016
}

var standardOfficeApps = []string{"Excel", "PowerPoint", "Word"}

// data type for a RegEx Path / Single Value DWORD combination
type OfficeRegistryRegExSingleDWORD struct {
	RootKey        registry.Key
	PathRegEx      string
	ValueName      string
	HardenedValue  uint32
	OfficeApps     []string
	OfficeVersions []string
	shortName      string
}

//// Office Packager Objects
// 0 - No prompt from Office when user clicks, object executes
// 1 - Prompt from Office when user clicks, object executes
// 2 - No prompt, Object does not execute
var OfficeOLE = OfficeRegistryRegExSingleDWORD{
	RootKey:        registry.CURRENT_USER,
	PathRegEx:      "SOFTWARE\\Microsoft\\Office\\%s\\%s\\Security",
	ValueName:      "PackagerPrompt",
	HardenedValue:  2,
	OfficeApps:     standardOfficeApps,
	OfficeVersions: standardOfficeVersions,
	shortName:      "OfficeOLE"}

//// Office Macros
// 1 - Enable all
// 2 - Disable with notification
// 3 - Digitally signed only
// 4 - Disable all
var OfficeMacros = OfficeRegistryRegExSingleDWORD{
	RootKey:        registry.CURRENT_USER,
	PathRegEx:      "SOFTWARE\\Microsoft\\Office\\%s\\%s\\Security",
	ValueName:      "VBAWarnings",
	HardenedValue:  4,
	OfficeApps:     standardOfficeApps,
	OfficeVersions: standardOfficeVersions,
	shortName:      "OfficeMacros"}

// Office ActiveX
var OfficeActiveX = RegistrySingleValueDWORD{
	RootKey:       registry.CURRENT_USER,
	Path:          "SOFTWARE\\Microsoft\\Office\\Common\\Security",
	ValueName:     "DisableAllActiveX",
	HardenedValue: 1,
	shortName:     "OfficeActiveX"}

//// DDE Mitigations for Word, Outlook and Excel
// Doesn't harden OneNote for now (due to high impact).
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
var pathRegExOptions = "SOFTWARE\\Microsoft\\Office\\%s\\%s\\Options"
var pathRegExWordMail = "SOFTWARE\\Microsoft\\Office\\%s\\%s\\Options\\WordMail"
var pathRegExSecurity = "Software\\Microsoft\\Office\\%s\\%s\\Security"
var pathWord2007 = "Software\\Microsoft\\Office\\12.0\\Word\\Options\\vpref"

var OfficeDDE = MultiHardenInterfaces{
	HardenInterfaces: []HardenInterface{
		OfficeRegistryRegExSingleDWORD{
			RootKey:       registry.CURRENT_USER,
			PathRegEx:     pathRegExOptions,
			ValueName:     "DontUpdateLinks",
			HardenedValue: 1,
			OfficeApps:    []string{"Word", "Excel"},
			OfficeVersions: []string{
				"14.0", // Office 2010
				"15.0", // Office 2013
				"16.0", // Office 2016
			},
			shortName: "OfficeDDE_DontUpdateLinksWordExcel"},

		OfficeRegistryRegExSingleDWORD{
			RootKey:       registry.CURRENT_USER,
			PathRegEx:     pathRegExWordMail,
			ValueName:     "DontUpdateLinks",
			HardenedValue: 1,
			OfficeApps:    []string{"Word"},
			OfficeVersions: []string{
				"14.0", // Office 2010
				"15.0", // Office 2013
				"16.0", // Office 2016
			},
			shortName: "OfficeDDE_DontUpdateLinksWordMail"},

		OfficeRegistryRegExSingleDWORD{
			RootKey:        registry.CURRENT_USER,
			PathRegEx:      pathRegExOptions,
			ValueName:      "DDEAllowed",
			HardenedValue:  0,
			OfficeApps:     []string{"Excel"},
			OfficeVersions: standardOfficeVersions,
			shortName:      "OfficeDDE_DDEAllowedExcel"},

		OfficeRegistryRegExSingleDWORD{
			RootKey:        registry.CURRENT_USER,
			PathRegEx:      pathRegExOptions,
			ValueName:      "DDECleaned",
			HardenedValue:  1,
			OfficeApps:     []string{"Excel"},
			OfficeVersions: standardOfficeVersions,
			shortName:      "OfficeDDE_DDECleanedExcel"},

		OfficeRegistryRegExSingleDWORD{
			RootKey:        registry.CURRENT_USER,
			PathRegEx:      pathRegExOptions,
			ValueName:      "Options",
			HardenedValue:  0x117,
			OfficeApps:     []string{"Excel"},
			OfficeVersions: standardOfficeVersions,
			shortName:      "OfficeDDE_OptionsExcel"},

		OfficeRegistryRegExSingleDWORD{
			RootKey:        registry.CURRENT_USER,
			PathRegEx:      pathRegExSecurity,
			ValueName:      "WorkbookLinkWarnings",
			HardenedValue:  2,
			OfficeApps:     []string{"Excel"},
			OfficeVersions: standardOfficeVersions,
			shortName:      "OfficeDDE_WorkbookLinksExcel"},

		RegistrySingleValueDWORD{
			RootKey:       registry.CURRENT_USER,
			Path:          pathWord2007,
			ValueName:     "fNoCalclinksOnopen_90_1",
			HardenedValue: 1,
			shortName:     "OfficeDDE_Word2007"},
	},
	shortName: "OfficeDDE",
}

//// HardenInterface methods

func (regValue OfficeRegistryRegExSingleDWORD) harden(harden bool) error {
	if harden {
		// harden
		for _, officeVersion := range regValue.OfficeVersions {
			for _, officeApp := range regValue.OfficeApps {
				path := fmt.Sprintf(regValue.PathRegEx, officeVersion, officeApp)
				key, _, _ := registry.CreateKey(regValue.RootKey, path, registry.ALL_ACCESS)
				// Save current state.
				saveOriginalRegistryDWORD(key, path, regValue.ValueName)
				// Harden.
				key.SetDWordValue(regValue.ValueName, regValue.HardenedValue)
				key.Close()
			}
		}
	} else {
		// restore
		for _, officeVersion := range regValue.OfficeVersions {
			for _, officeApp := range regValue.OfficeApps {
				path := fmt.Sprintf(regValue.PathRegEx, officeVersion, officeApp)
				key, _ := registry.OpenKey(regValue.RootKey, path, registry.ALL_ACCESS)
				// restore previous state
				restoreKey(key, path, regValue.ValueName)
				key.Close()
			}
		}
	}

	return nil
}

func (officeRegEx OfficeRegistryRegExSingleDWORD) isHardened() bool {
	var hardened = true

	for _, officeVersion := range officeRegEx.OfficeVersions {
		for _, officeApp := range officeRegEx.OfficeApps {
			path := fmt.Sprintf(officeRegEx.PathRegEx, officeVersion, officeApp)
			key, err := registry.OpenKey(officeRegEx.RootKey, path, registry.READ)
			if err == nil {
				currentValue, _, err := key.GetIntegerValue(officeRegEx.ValueName)
				if err == nil {
					if uint32(currentValue) != officeRegEx.HardenedValue {
						hardened = false
					}
				} else {
					hardened = false
				}
			} else {
				hardened = false
			}
			key.Close()
		}
	}
	return hardened
}

func (officeRegEx OfficeRegistryRegExSingleDWORD) name() string {
	return officeRegEx.shortName
}
