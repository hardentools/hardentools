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

// Available office versions.
var standardOfficeVersions = []string{
	"12.0", // Office 2007.
	"14.0", // Office 2010.
	"15.0", // Office 2013.
	"16.0", // Office 2016, 2019 and Office365 (local client).
}

// Standard office apps to harden.
var standardOfficeApps = []string{"Excel", "PowerPoint", "Word"}

// OfficeRegistryRegExSingleDWORD is the data type for a RegEx Path / Single
// Value DWORD combination.
type OfficeRegistryRegExSingleDWORD struct {
	RootKey         registry.Key
	PathRegEx       string
	ValueName       string
	HardenedValue   uint32
	OfficeApps      []string
	OfficeVersions  []string
	shortName       string
	longName        string
	description     string
	hardenByDefault bool
}

// OfficeOLE hardens Office Packager Objects.
// 0 - No prompt from Office when user clicks, object executes.
// 1 - Prompt from Office when user clicks, object executes.
// 2 - No prompt, Object does not execute.
var OfficeOLE = &OfficeRegistryRegExSingleDWORD{
	RootKey:         registry.CURRENT_USER,
	PathRegEx:       "SOFTWARE\\Microsoft\\Office\\%s\\%s\\Security",
	ValueName:       "PackagerPrompt",
	HardenedValue:   2,
	OfficeApps:      standardOfficeApps,
	OfficeVersions:  standardOfficeVersions,
	shortName:       "Office OLE",
	longName:        "Office Packager Objects (OLE)",
	hardenByDefault: true,
}

// OfficeMacros contains Macro registry keys.
// 1 - Enable all.
// 2 - Disable with notification.
// 3 - Digitally signed only.
// 4 - Disable all.
var OfficeMacros = &OfficeRegistryRegExSingleDWORD{
	RootKey:         registry.CURRENT_USER,
	PathRegEx:       "SOFTWARE\\Microsoft\\Office\\%s\\%s\\Security",
	ValueName:       "VBAWarnings",
	HardenedValue:   4,
	OfficeApps:      standardOfficeApps,
	OfficeVersions:  standardOfficeVersions,
	shortName:       "Office Macros",
	longName:        "Office Macros",
	hardenByDefault: true,
}

// OfficeActiveX contains ActiveX registry keys.
var OfficeActiveX = &RegistrySingleValueDWORD{
	RootKey:         registry.CURRENT_USER,
	Path:            "SOFTWARE\\Microsoft\\Office\\Common\\Security",
	ValueName:       "DisableAllActiveX",
	HardenedValue:   1,
	shortName:       "Office ActiveX",
	longName:        "Office ActiveX",
	hardenByDefault: true,
}

// DDE Mitigations for Word, Outlook and Excel
// Doesn't harden OneNote for now (due to high impact).
//
// Microsoft disabled DDE in Word with Office Update ADV170021 update. We make sure
// that it is in default (disabled) state. This update adds a new Windows registry
// key that controls the DDE feature's status for the Word app. The default value
// disables DDE. Here are registry key's values:
// [HKEY_CURRENT_USER\Software\Microsoft\Office\%s\Word\Security] AllowDDE(DWORD)
// AllowDDE(DWORD) = 0: To disable DDE. This is the default setting after you install the update.
// AllowDDE(DWORD) = 1: To allow DDE requests to an already running program, but prevent DDE requests that require another executable program to be launched.
// AllowDDE(DWORD) = 2: To fully allow DDE requests.
// On 1/9/2018, Microsoft released an update for Microsoft Office that adds defense-in-depth configuration options to selectively disable the DDE protocol in all supported editions of Microsoft Excel.
// If you need to change DDE functionality in Excel after installing the update, follow these steps:
// In the Registry Editor navigate to \HKEY_CURRENT_USER\Software\Microsoft\Office&lt;version>\Excel\Security DisableDDEServerLaunch(DWORD)
// Set the DWORD value based on your requirements as follows:
// DisableDDEServerLaunch = 0: Keep DDE server launch settings unchanged from their initial behavior. This is the default setting after you install the update.
// DisableDDEServerLaunch = 1: Do not display the dialog that allows users to choose whether to launch a specific DDE server. Instead, behave automatically as though the user chose the default choice of NO.
// In the Registry Editor navigate to \HKEY_CURRENT_USER\Software\Microsoft\Office&lt;version>\Excel\Security DisableDDEServerLookup(DWORD)
// Set the DWORD value based on your requirements as follows:
// DisableDDEServerLookup = 0: Keep DDE server lookup settings unchanged from their initial behavior. This is the default setting after you install the update.
// DisableDDEServerLookup = 1: Disable querying for DDE Server availability - no query attempt will be made to find DDE servers. .

//
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

var (
	pathRegExOptions  = "SOFTWARE\\Microsoft\\Office\\%s\\%s\\Options"
	pathRegExWordMail = "SOFTWARE\\Microsoft\\Office\\%s\\%s\\Options\\WordMail"
	pathRegExSecurity = "Software\\Microsoft\\Office\\%s\\%s\\Security"
	pathWord2007      = "Software\\Microsoft\\Office\\12.0\\Word\\Options\\vpref"
)

// OfficeDDE contains the registry keys for DDE hardening
// please also refer to
// https://docs.microsoft.com/en-us/security-updates/securityadvisories/2017/4053440
var OfficeDDE = &MultiHardenInterfaces{
	hardenInterfaces: []HardenInterface{
		// AllowDDE: part of Update ADV170021
		// disables DDE for Word (default setting after installation of update)
		&OfficeRegistryRegExSingleDWORD{
			RootKey:       registry.CURRENT_USER,
			PathRegEx:     pathRegExSecurity,
			ValueName:     "AllowDDE",
			HardenedValue: 0,
			OfficeApps:    []string{"Word"},
			OfficeVersions: []string{
				"14.0", // Office 2010
				"15.0", // Office 2013
				"16.0", // Office 2016
			},
			shortName: "OfficeDDE_AllowDDE_Word",
		},
		// DisableDDEServerLaunch: part of  Update ADV170021
		// "0" reflects Microsoft standard settings. If you want to further harden
		// your settings you could use "1" and uncomment this
		//&OfficeRegistryRegExSingleDWORD{
		//	RootKey:       registry.CURRENT_USER,
		//	PathRegEx:     pathRegExSecurity,
		//	ValueName:     "DisableDDEServerLaunch",
		//	HardenedValue: 0,
		//	OfficeApps:    []string{"Excel"},
		//	OfficeVersions: []string{
		//		"14.0", // Office 2010
		//		"15.0", // Office 2013
		//		"16.0", // Office 2016
		//	},
		//	shortName: "OfficeDDE_DDEServer_Excel1",
		//},
		// DisableDDEServerLookup: part of  Update ADV170021
		// "0" reflects Microsoft standard settings. If you want to further harden
		// your settings you could use "1" and uncomment this
		//&OfficeRegistryRegExSingleDWORD{
		//	RootKey:       registry.CURRENT_USER,
		//	PathRegEx:     pathRegExSecurity,
		//	ValueName:     "DisableDDEServerLookup",
		//	HardenedValue: 0,
		//	OfficeApps:    []string{"Excel"},
		//	OfficeVersions: []string{
		//		"14.0", // Office 2010
		//		"15.0", // Office 2013
		//		"16.0", // Office 2016
		//	},
		//	shortName: "OfficeDDE_DDEServer_Excel2",
		//},
		// the following setting has been removed, because it causes excel files
		// that are opened in Windows Explorer not loading anymore (excel is
		// started, but file is not opened (which is very inconvenient/unexpected)
		// -> https://social.technet.microsoft.com/Forums/en-US/ec1d2f20-ec8a-4c3b-
		//    9e1b-ee731981db7c/double-clicking-xlsx-files-opens-a-blank-excel-page
		//&OfficeRegistryRegExSingleDWORD{
		//	RootKey:        registry.CURRENT_USER,
		//	PathRegEx:      pathRegExOptions,
		//	ValueName:      "DDEAllowed",
		//	HardenedValue:  0,
		//	OfficeApps:     []string{"Excel"},
		//	OfficeVersions: standardOfficeVersions,
		//	shortName:      "OfficeDDE_DDEAllowedExcel",
		//},
		// the following setting has been removed, because it causes excel files
		// that are opened in Windows Explorer not loading anymore (excel is
		// started, but file is not opened (which is very inconvenient/unexpected)
		// -> https://social.technet.microsoft.com/Forums/en-US/ec1d2f20-ec8a-4c3b-
		//    9e1b-ee731981db7c/double-clicking-xlsx-files-opens-a-blank-excel-page
		//&OfficeRegistryRegExSingleDWORD{
		//	RootKey:        registry.CURRENT_USER,
		//	PathRegEx:      pathRegExOptions,
		//	ValueName:      "DDECleaned",
		//	HardenedValue:  1,
		//	OfficeApps:     []string{"Excel"},
		//	OfficeVersions: standardOfficeVersions,
		//	shortName:      "OfficeDDE_DDECleanedExcel",
		//},
		// the following setting has been removed, because it causes excel files
		// that are opened in Windows Explorer not loading anymore (excel is
		// started, but file is not opened (which is very inconvenient/unexpected)
		//&OfficeRegistryRegExSingleDWORD{
		//	RootKey:        registry.CURRENT_USER,
		//	PathRegEx:      pathRegExOptions,
		//	ValueName:      "Options",
		//	HardenedValue:  0x117,
		//	OfficeApps:     []string{"Excel"},
		//	OfficeVersions: standardOfficeVersions,
		//	shortName:      "OfficeDDE_OptionsExcel",
		//},

		// WorkbookLinkWarnings
		// Impact of mitigation: Disabling this feature could prevent Excel
		// spreadsheets from updating dynamically if disabled in the registry.
		// Data might not be completely up-to-date because it is no longer being
		// updated automatically via live feed. To update the worksheet, the user
		// must start the feed manually. In addition, the user will not receive
		// prompts to remind them to manually update the worksheet.
		&OfficeRegistryRegExSingleDWORD{
			RootKey:        registry.CURRENT_USER,
			PathRegEx:      pathRegExSecurity,
			ValueName:      "WorkbookLinkWarnings",
			HardenedValue:  2,
			OfficeApps:     []string{"Excel"},
			OfficeVersions: standardOfficeVersions,
			shortName:      "OfficeDDE_WorkbookLinksExcel",
		},
		// fNoCalclinksOnopen_90_1 & DontUpdateLinks:
		// Impact of mitigation: Setting this registry key will disable automatic
		// update for DDE field and OLE links. Users can still enable the update by
		// right-clicking on the field and clicking “Update Field”.
		&OfficeRegistryRegExSingleDWORD{
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
			shortName: "OfficeDDE_DontUpdateLinksWordExcel",
		},
		&OfficeRegistryRegExSingleDWORD{
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
			shortName: "OfficeDDE_DontUpdateLinksWordMail",
		},
		&RegistrySingleValueDWORD{
			RootKey:       registry.CURRENT_USER,
			Path:          pathWord2007,
			ValueName:     "fNoCalclinksOnopen_90_1",
			HardenedValue: 1,
			shortName:     "OfficeDDE_Word2007",
		},
	},
	shortName:       "Office DDE",
	longName:        "Office DDE Mitigations",
	hardenByDefault: true,
}

// Harden hardens OfficeRegistryRegExSingleDWORD registry values.
func (officeRegEx OfficeRegistryRegExSingleDWORD) Harden(harden bool) error {
	for _, officeVersion := range officeRegEx.OfficeVersions {
		for _, officeApp := range officeRegEx.OfficeApps {
			path := fmt.Sprintf(officeRegEx.PathRegEx, officeVersion, officeApp)

			// Build a RegistrySingleValueDWORD so we can reuse the Harden() method.
			var singleDWORD = &RegistrySingleValueDWORD{
				RootKey:       officeRegEx.RootKey,
				Path:          path,
				ValueName:     officeRegEx.ValueName,
				HardenedValue: officeRegEx.HardenedValue,
				shortName:     officeRegEx.shortName,
				longName:      officeRegEx.longName,
				description:   officeRegEx.description,
			}

			// Call RegistrySingleValueDWORD Harden method to Harden or Restore.
			err := singleDWORD.Harden(harden)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

// IsHardened verifies if OfficeRegistryRegExSingleDWORD is already hardened.
func (officeRegEx OfficeRegistryRegExSingleDWORD) IsHardened() bool {
	var hardened = true

	for _, officeVersion := range officeRegEx.OfficeVersions {
		for _, officeApp := range officeRegEx.OfficeApps {
			path := fmt.Sprintf(officeRegEx.PathRegEx, officeVersion, officeApp)

			// Build a RegistrySingleValueDWORD so we can reuse the isHardened() method.
			var singleDWORD = &RegistrySingleValueDWORD{
				RootKey:       officeRegEx.RootKey,
				Path:          path,
				ValueName:     officeRegEx.ValueName,
				HardenedValue: officeRegEx.HardenedValue,
			}

			if !singleDWORD.IsHardened() {
				hardened = false
			}
		}
	}
	return hardened
}

// Name returns the (short) name of the harden item.
func (officeRegEx OfficeRegistryRegExSingleDWORD) Name() string {
	return officeRegEx.shortName
}

// LongName returns the long name of the harden item.
func (officeRegEx OfficeRegistryRegExSingleDWORD) LongName() string {
	return officeRegEx.longName
}

// Description of the harden item.
func (officeRegEx OfficeRegistryRegExSingleDWORD) Description() string {
	return officeRegEx.description
}

// HardenByDefault returns if subject should be hardened by default.
func (officeRegEx OfficeRegistryRegExSingleDWORD) HardenByDefault() bool {
	return officeRegEx.hardenByDefault
}
