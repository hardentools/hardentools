// Hardentools
// Copyright (C) 2017-2021 Security Without Borders
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

var standardAdobeVersions = []string{
	"DC",   // Acrobat Reader DC.
	"2020", // Acrobat Reader 2020
	"XI",   // Acrobat Reader XI (outdated)
}

// AdobeRegistryRegExSingleDWORD is the data type for a RegEx Path and
// Single Value DWORD combination.
type AdobeRegistryRegExSingleDWORD struct {
	RootKey         registry.Key
	PathRegEx       string
	ValueName       string
	HardenedValue   uint32
	AdobeVersions   []string
	shortName       string
	longName        string
	description     string
	hardenByDefault bool
}

// AdobePDFJS hardens Acrobat JavaScript.
// bEnableJS possible values:
// 0 - Disable AcroJS
// 1 - Enable AcroJS
var AdobePDFJS = &AdobeRegistryRegExSingleDWORD{
	RootKey:         registry.CURRENT_USER,
	PathRegEx:       "SOFTWARE\\Adobe\\Acrobat Reader\\%s\\JSPrefs",
	ValueName:       "bEnableJS",
	HardenedValue:   0, // Disable AcroJS
	AdobeVersions:   standardAdobeVersions,
	shortName:       "Adobe JavaScript",
	longName:        "Acrobat Reader JavaScript",
	description:     "Disables Acrobat Reader JavaScript",
	hardenByDefault: true,
}

// AdobePDFObjects hardens Adobe Reader Embedded Objects.
// bAllowOpenFile set to 0 and
// bSecureOpenFile set to 1 to disable
// the opening of non-PDF documents
var AdobePDFObjects = &MultiHardenInterfaces{
	hardenInterfaces: []HardenInterface{
		&AdobeRegistryRegExSingleDWORD{
			RootKey:       registry.CURRENT_USER,
			PathRegEx:     "SOFTWARE\\Adobe\\Acrobat Reader\\%s\\Originals",
			ValueName:     "bAllowOpenFile",
			HardenedValue: 0,
			AdobeVersions: standardAdobeVersions,
			shortName:     "AdobePDFObjects_bAllowOpenFile",
		},
		&AdobeRegistryRegExSingleDWORD{
			RootKey:       registry.CURRENT_USER,
			PathRegEx:     "SOFTWARE\\Adobe\\Acrobat Reader\\%s\\Originals",
			ValueName:     "bSecureOpenFile",
			HardenedValue: 1,
			AdobeVersions: standardAdobeVersions,
			shortName:     "AdobePDFObjects_bSecureOpenFile",
		},
	},
	shortName:       "Adobe Objects",
	longName:        "Acrobat Reader Embedded Objects",
	description:     "Disables Acrobat Reader embedded objects",
	hardenByDefault: true,
}

// AdobePDFProtectedMode switches on the Protected Mode setting under
// "Security (Enhanced)" (enabled by default in current versions).
// (HKEY_LOCAL_USER\Software\Adobe\Acrobat Reader<version>\Privileged -> DWORD „bProtectedMode“)
// 0 - Disable Protected Mode
// 1 - Enable Protected Mode
var AdobePDFProtectedMode = &AdobeRegistryRegExSingleDWORD{
	RootKey:         registry.CURRENT_USER,
	PathRegEx:       "SOFTWARE\\Adobe\\Acrobat Reader\\%s\\Privileged",
	ValueName:       "bProtectedMode",
	HardenedValue:   1,
	AdobeVersions:   standardAdobeVersions,
	shortName:       "Adobe Protected Mode",
	longName:        "Acrobat Reader Protected Mode",
	description:     "Enables Acrobat Reader Protected Mode",
	hardenByDefault: true,
}

// AdobePDFProtectedView switches on Protected View for all files from
// untrusted sources.
// (HKEY_CURRENT_USER\SOFTWARE\Adobe\Acrobat Reader\<version>\TrustManager -> iProtectedView)
// 0 - Disable Protected View
// 1 - Enable Protected View
var AdobePDFProtectedView = &AdobeRegistryRegExSingleDWORD{
	RootKey:         registry.CURRENT_USER,
	PathRegEx:       "SOFTWARE\\Adobe\\Acrobat Reader\\%s\\TrustManager",
	ValueName:       "iProtectedView",
	HardenedValue:   1,
	AdobeVersions:   standardAdobeVersions,
	shortName:       "Adobe Protected View",
	longName:        "Acrobat Reader Protected View",
	description:     "Enables Acrobat Reader Protected View",
	hardenByDefault: true,
}

// AdobePDFEnhancedSecurity switches on Enhanced Security setting under
// "Security (Enhanced)".
// (enabled by default in current versions)
// (HKEY_CURRENT_USER\SOFTWARE\Adobe\Acrobat Reader\DC\TrustManager -> bEnhancedSecurityInBrowser = 1 & bEnhancedSecurityStandalone = 1)
var AdobePDFEnhancedSecurity = &MultiHardenInterfaces{
	shortName:       "Adobe Enhanced Security",
	longName:        "Acrobat Reader Enhanced Security",
	description:     "Enables Acrobat Reader Enhanced Security",
	hardenByDefault: true,
	hardenInterfaces: []HardenInterface{
		&AdobeRegistryRegExSingleDWORD{
			RootKey:       registry.CURRENT_USER,
			PathRegEx:     "SOFTWARE\\Adobe\\Acrobat Reader\\%s\\TrustManager",
			ValueName:     "bEnhancedSecurityInBrowser",
			HardenedValue: 1,
			AdobeVersions: standardAdobeVersions,
			shortName:     "AdobePDFEnhancedSecurity_bEnhancedSecurityInBrowser",
		},
		&AdobeRegistryRegExSingleDWORD{
			RootKey:       registry.CURRENT_USER,
			PathRegEx:     "SOFTWARE\\Adobe\\Acrobat Reader\\%s\\TrustManager",
			ValueName:     "bEnhancedSecurityStandalone",
			HardenedValue: 1,
			AdobeVersions: standardAdobeVersions,
			shortName:     "AdobePDFEnhancedSecurity_bEnhancedSecurityStandalone",
		},
	},
}

// Harden hardens / restores AdobeRegistryRegExSingleDWORD registry keys.
func (adobeRegEx *AdobeRegistryRegExSingleDWORD) Harden(harden bool) error {
	// Harden.
	for _, adobeVersion := range adobeRegEx.AdobeVersions {
		path := fmt.Sprintf(adobeRegEx.PathRegEx, adobeVersion)

		// Build a RegistrySingleValueDWORD so we can reuse the Harden() method.
		var singleDWORD = &RegistrySingleValueDWORD{
			RootKey:       adobeRegEx.RootKey,
			Path:          path,
			ValueName:     adobeRegEx.ValueName,
			HardenedValue: adobeRegEx.HardenedValue,
			shortName:     adobeRegEx.shortName,
			longName:      adobeRegEx.longName,
			description:   adobeRegEx.description,
		}

		// Call RegistrySingleValueDWORD Harden method to Harden or Restore.
		err := singleDWORD.Harden(harden)
		if err != nil {
			return err
		}
	}

	return nil
}

// IsHardened checks if AdobeRegistryRegExSingleDWORD is hardened.
func (adobeRegEx *AdobeRegistryRegExSingleDWORD) IsHardened() bool {
	var hardened = true

	for _, adobeVersion := range adobeRegEx.AdobeVersions {
		path := fmt.Sprintf(adobeRegEx.PathRegEx, adobeVersion)

		// Build a RegistrySingleValueDWORD so we can reuse the isHardened()
		// method.
		var singleDWORD = &RegistrySingleValueDWORD{
			RootKey:       adobeRegEx.RootKey,
			Path:          path,
			ValueName:     adobeRegEx.ValueName,
			HardenedValue: adobeRegEx.HardenedValue,
			shortName:     adobeRegEx.shortName,
			longName:      adobeRegEx.longName,
			description:   adobeRegEx.description,
		}

		if !singleDWORD.IsHardened() {
			hardened = false
		}
	}
	return hardened
}

// Name returns name of hardening modulels.
func (adobeRegEx *AdobeRegistryRegExSingleDWORD) Name() string {
	return adobeRegEx.shortName
}

// LongName returns LongName of hardening module.
func (adobeRegEx *AdobeRegistryRegExSingleDWORD) LongName() string {
	return adobeRegEx.longName
}

// Description return description of hardening module.
func (adobeRegEx *AdobeRegistryRegExSingleDWORD) Description() string {
	return adobeRegEx.description
}

// HardenByDefault returns if subject should be hardened by default.
func (adobeRegEx *AdobeRegistryRegExSingleDWORD) HardenByDefault() bool {
	return adobeRegEx.hardenByDefault
}
