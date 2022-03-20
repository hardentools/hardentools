// Hardentools
// Copyright (C) 2017-2022 Security Without Borders
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

// :: Enable Defender signatures for Potentially Unwanted Applications (PUA)
// HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender
// PUAProtection DWORD 1 (= enable) (2 = Audit Mode)
// HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\MpEngine
// MpEnablePus DWORD 1
//
// alternatively one can use (not used in hardentools):
// powershell.exe Set-MpPreference -PUAProtection enable
//
// test via : https://www.amtso.org/feature-settings-check-potentially-unwanted-applications/
//
// Further literature:
// https://docs.microsoft.com/de-de/microsoft-365/security/defender-endpoint/detect-block-potentially-unwanted-apps-microsoft-defender-antivirus?view=o365-worldwide
// https://www.deskmodder.de/blog/2018/08/20/pua-schutzfunktion-im-windows-defender-aktivieren-windows-10/
// https://admx.help/?Category=Windows_10_2016&Policy=Microsoft.Policies.WindowsDefender::Root_PUAProtection&Language=de-de
// https://social.technet.microsoft.com/wiki/contents/articles/32909.windows-defender-how-to-activate-potentially-unwanted-applications-pua-protection.aspx

import (
	"golang.org/x/sys/windows/registry"
)

// PUA contains the registry keys to be hardened.
var PUA = &MultiHardenInterfaces{
	hardenInterfaces: []HardenInterface{
		&RegistrySingleValueDWORD{
			RootKey:         registry.LOCAL_MACHINE,
			Path:            "SOFTWARE\\Policies\\Microsoft\\Windows Defender",
			ValueName:       "PUAProtection",
			HardenedValue:   1,
			shortName:       "Defender PUA",
			longName:        "Defender PUA Protection",
			hardenByDefault: false,
		},
		&RegistrySingleValueDWORD{
			RootKey: registry.LOCAL_MACHINE,
			Path:    "SOFTWARE\\Policies\\Microsoft\\Windows Defender\\MpEngine",
			// MpEnablePus DWORD 1",
			ValueName:       "MpEnablePus",
			shortName:       "Defender PUA MpEnablePus",
			longName:        "Defender PUA MpEnablePus",
			hardenByDefault: false,
		},
	},
	shortName:       "Defender PUA Protection",
	longName:        "Defender Potentially Unwanted Applications Protection",
	hardenByDefault: false,
}
