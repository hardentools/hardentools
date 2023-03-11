// Hardentools
// Copyright (C) 2023 Security Without Borders
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
var standardOfficeApps = []string{"onenote"}

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

// OneNoteBlockExtensions blocks certain types of files in OneNote client
var OneNoteBlockExtensions = &OfficeRegistryRegExSingleDWORD{
	RootKey:        registry.CURRENT_USER,
	PathRegEx:      "SOFTWARE\\Policies\\Microsoft\\office\\%s\\%s\\options\\embeddedfileopenoptions",
	ValueName:      "blockedextensions",
	HardenedValue:  ".hta;.JSE;.js;.exe;.bat;.vbs;.com;.scf;.VBE;.scr;.cmd;.mht;.ps1;.pif;.WSH;.WSF;.lnk",
	OfficeApps:     standardOfficeApps,
	OfficeVersions: standardOfficeVersions,
	shortName:      "OneNote Block Extensions",
	longName:       "Block specific file types in OneNote attachments",
	description: "Disables opening the following file types as OneNote attachments: " +
		".hta;.JSE;.js;.exe;.bat;.vbs;.com;.scf;.VBE;.scr;.cmd;.mht;.ps1;.pif;.WSH;.WSF;.lnk",
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
