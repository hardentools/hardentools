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
	"golang.org/x/sys/windows/registry"
)

// UAC is a Multi Value Registry struct for UAC registry keys.
var UAC = &MultiHardenInterfaces{
	hardenInterfaces: []HardenInterface{
		&RegistrySingleValueDWORD{
			RootKey:         registry.LOCAL_MACHINE,
			Path:            "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
			ValueName:       "ConsentPromptBehaviorAdmin",
			HardenedValue:   3,
			shortName:       "UAC Prompt",
			longName:        "UAC Prompt",
			hardenByDefault: true,
		},
		&RegistrySingleValueDWORD{
			RootKey:         registry.LOCAL_MACHINE,
			Path:            "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
			ValueName:       "PromptOnSecureDesktop",
			HardenedValue:   1,
			shortName:       "UAC SecureDesktop",
			longName:        "UAC PromptOnSecureDesktop",
			hardenByDefault: true,
		},
		&RegistrySingleValueDWORD{
			RootKey:         registry.LOCAL_MACHINE,
			Path:            "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
			ValueName:       "EnableLUA",
			HardenedValue:   1,
			shortName:       "UAC EnableLUA",
			longName:        "UAC EnableLUA",
			hardenByDefault: true,
		},
	},
	shortName:       "UAC",
	longName:        "User Account Control",
	description:     "Enables UAC with secure desktop and admin password",
	hardenByDefault: true,
}
