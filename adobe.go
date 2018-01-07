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

var standardAdobeVersions = []string{
	"DC", // Acrobat Reader DC
	"XI", // Acrobat Reader XI
}

// data type for a RegEx Path / Single Value DWORD combination
type AdobeRegistryRegExSingleDWORD struct {
	RootKey       registry.Key
	PathRegEx     string
	ValueName     string
	HardenedValue uint32
	AdobeVersions []string
	shortName     string
	longName      string
	description   string
}

// bEnableJS possible values:
// 0 - Disable AcroJS
// 1 - Enable AcroJS
var AdobePDFJS = &AdobeRegistryRegExSingleDWORD{
	RootKey:       registry.CURRENT_USER,
	PathRegEx:     "SOFTWARE\\Adobe\\Acrobat Reader\\%s\\JSPrefs",
	ValueName:     "bEnableJS",
	HardenedValue: 0, // Disable AcroJS
	AdobeVersions: standardAdobeVersions,
	shortName:     "AdobePDFJS",
	longName:      "Acrobat Reader JavaScript",
	description:   "Disables Acrobat Reader JavaScript"}

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
			shortName:     "AdobePDFObjects_bAllowOpenFile"},
		&AdobeRegistryRegExSingleDWORD{
			RootKey:       registry.CURRENT_USER,
			PathRegEx:     "SOFTWARE\\Adobe\\Acrobat Reader\\%s\\Originals",
			ValueName:     "bSecureOpenFile",
			HardenedValue: 1,
			AdobeVersions: standardAdobeVersions,
			shortName:     "AdobePDFObjects_bSecureOpenFile"},
	},
	shortName:   "AdobePDFObjects",
	longName:    "Acrobat Reader Embedded Objects",
	description: "Disables Acrobat Reader embedded objects",
}

// Switch on the Protected Mode setting under "Security (Enhanced)" (enabled by default in current versions)
// (HKEY_LOCAL_USER\Software\Adobe\Acrobat Reader<version>\Privileged -> DWORD „bProtectedMode“)
// 0 - Disable Protected Mode
// 1 - Enable Protected Mode
var AdobePDFProtectedMode = &AdobeRegistryRegExSingleDWORD{
	RootKey:       registry.CURRENT_USER,
	PathRegEx:     "SOFTWARE\\Adobe\\Acrobat Reader\\%s\\Privileged",
	ValueName:     "bProtectedMode",
	HardenedValue: 1,
	AdobeVersions: standardAdobeVersions,
	shortName:     "AdobePDFProtectedMode",
	longName:      "Acrobat Reader Protected Mode",
	description:   "Enables Acrobat Reader Protected Mode"}

// Switch on Protected View for all files from untrusted sources
// (HKEY_CURRENT_USER\SOFTWARE\Adobe\Acrobat Reader\<version>\TrustManager -> iProtectedView)
// 0 - Disable Protected View
// 1 - Enable Protected View
var AdobePDFProtectedView = &AdobeRegistryRegExSingleDWORD{
	RootKey:       registry.CURRENT_USER,
	PathRegEx:     "SOFTWARE\\Adobe\\Acrobat Reader\\%s\\TrustManager",
	ValueName:     "iProtectedView",
	HardenedValue: 1,
	AdobeVersions: standardAdobeVersions,
	shortName:     "AdobePDFProtectedView",
	longName:      "Acrobat Reader Protected View",
	description:   "Enables Acrobat Reader Protected View"}

// Switch on Enhanced Security setting under "Security (Enhanced)"
// (enabled by default in current versions)
// (HKEY_CURRENT_USER\SOFTWARE\Adobe\Acrobat Reader\DC\TrustManager -> bEnhancedSecurityInBrowser = 1 & bEnhancedSecurityStandalone = 1)
var AdobePDFEnhancedSecurity = &MultiHardenInterfaces{
	shortName:   "AdobePDFEnhancedSecurity",
	longName:    "Acrobat Reader Enhanced Security",
	description: "Enables Acrobat Reader Enhanced Security",
	hardenInterfaces: []HardenInterface{
		&AdobeRegistryRegExSingleDWORD{
			RootKey:       registry.CURRENT_USER,
			PathRegEx:     "SOFTWARE\\Adobe\\Acrobat Reader\\%s\\TrustManager",
			ValueName:     "bEnhancedSecurityInBrowser",
			HardenedValue: 1,
			AdobeVersions: standardAdobeVersions,
			shortName:     "AdobePDFEnhancedSecurity_bEnhancedSecurityInBrowser"},
		&AdobeRegistryRegExSingleDWORD{
			RootKey:       registry.CURRENT_USER,
			PathRegEx:     "SOFTWARE\\Adobe\\Acrobat Reader\\%s\\TrustManager",
			ValueName:     "bEnhancedSecurityStandalone",
			HardenedValue: 1,
			AdobeVersions: standardAdobeVersions,
			shortName:     "AdobePDFEnhancedSecurity_bEnhancedSecurityStandalone"},
	},
}

//// HardenInterface methods

func (adobeRegEx *AdobeRegistryRegExSingleDWORD) Harden(harden bool) error {
	if harden {
		// Harden.
		for _, adobeVersion := range adobeRegEx.AdobeVersions {
			path := fmt.Sprintf(adobeRegEx.PathRegEx, adobeVersion)
			err := HardenDwordValue(adobeRegEx.RootKey, path, adobeRegEx.ValueName, adobeRegEx.HardenedValue)
			if err != nil {
				return err
			}
			/*
				key, _, _ := registry.CreateKey(adobeRegEx.RootKey, path, registry.ALL_ACCESS)
				defer key.Close()

				err := saveOriginalRegistryDWORD(adobeRegEx.RootKey, path, adobeRegEx.ValueName)
				if err != nil {
					return err
				}

				err = key.SetDWordValue(adobeRegEx.ValueName, adobeRegEx.HardenedValue)
				if err != nil {
					log.Println("Error when hardening registry value " + adobeRegEx.ValueName + " = " + strconv.FormatUint(uint64(adobeRegEx.HardenedValue), 16))
					return err
				}*/
		}
	} else {
		// Restore.
		for _, adobeVersion := range adobeRegEx.AdobeVersions {
			path := fmt.Sprintf(adobeRegEx.PathRegEx, adobeVersion)

			err := restoreKey(adobeRegEx.RootKey, path, adobeRegEx.ValueName)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func (adobeRegEx *AdobeRegistryRegExSingleDWORD) IsHardened() bool {
	var hardened = true

	for _, adobeVersion := range adobeRegEx.AdobeVersions {
		path := fmt.Sprintf(adobeRegEx.PathRegEx, adobeVersion)
		key, err := registry.OpenKey(adobeRegEx.RootKey, path, registry.READ)
		if err == nil {
			currentValue, _, err := key.GetIntegerValue(adobeRegEx.ValueName)
			if err == nil {
				if uint32(currentValue) != adobeRegEx.HardenedValue {
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
	return hardened
}

func (adobeRegEx *AdobeRegistryRegExSingleDWORD) Name() string {
	return adobeRegEx.shortName
}

func (adobeRegEx *AdobeRegistryRegExSingleDWORD) LongName() string {
	return adobeRegEx.longName
}

func (adobeRegEx *AdobeRegistryRegExSingleDWORD) Description() string {
	return adobeRegEx.description
}
