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
	"golang.org/x/sys/windows/registry"
)

// Autorun

// - HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer!NoDriveTypeAutoRun
// - HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer!NoAutorun
// - HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers!DisableAutoplay 1

// Autorun is a Multi Value Registry struct for autorun registry keys.
var Autorun = &RegistryMultiValue{
	ArraySingleDWORD: []*RegistrySingleValueDWORD{
		{
			RootKey:       registry.CURRENT_USER,
			Path:          "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer",
			ValueName:     "NoDriveTypeAutoRun",
			HardenedValue: 0xb5,
			shortName:     "Autorun_NoDriveTypeAutoRun",
		},
		{
			RootKey:       registry.CURRENT_USER,
			Path:          "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer",
			ValueName:     "NoAutorun",
			HardenedValue: 1,
			shortName:     "Autorun_NoAutorun",
		},
		{
			RootKey:       registry.CURRENT_USER,
			Path:          "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\AutoplayHandlers",
			ValueName:     "DisableAutoplay",
			HardenedValue: 1,
			shortName:     "Autorun_Autoplay",
		},
	},
	shortName:       "Autorun",
	longName:        "AutoRun and AutoPlay",
	hardenByDefault: true,
}
