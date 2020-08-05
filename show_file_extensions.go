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

// ShowFileExt contains the Unhide Explorer File Extensions registry keys.
var ShowFileExt = &RegistryMultiValue{
	ArraySingleDWORD: []*RegistrySingleValueDWORD{
		{
			RootKey:       registry.CURRENT_USER,
			Path:          "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced",
			ValueName:     "HideFileExt",
			HardenedValue: 0x00000000,
			shortName:     "ShowFileExt_FileExt",
		},
		{
			RootKey:       registry.CURRENT_USER,
			Path:          "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced",
			ValueName:     "Hidden",
			HardenedValue: 0x00000001,
			shortName:     "ShowFileExt_Hidden",
		},
		{
			RootKey:       registry.CURRENT_USER,
			Path:          "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced",
			ValueName:     "ShowSuperHidden",
			HardenedValue: 0x00000001,
			shortName:     "ShowFileExt_SuperHidden",
		},
	},
	shortName:       "Show File Ext",
	longName:        "Show File Extensions",
	hardenByDefault: true,
}
