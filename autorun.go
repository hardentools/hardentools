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
	"golang.org/x/sys/windows/registry"
)

// Autorun

// - HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer!NoDriveTypeAutoRun
// - HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer!NoAutorun
// - HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers!DisableAutoplay 1

func triggerAutorun(harden bool) {
	var keyAutorunName = "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer"
	keyAutorun, _, _ := registry.CreateKey(registry.CURRENT_USER, keyAutorunName, registry.ALL_ACCESS)
	var keyAutoplayName = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\AutoplayHandlers"
	keyAutoplay, _, _ := registry.CreateKey(registry.CURRENT_USER, keyAutoplayName, registry.ALL_ACCESS)

	if harden == false {
		events.AppendText("Restoring original settings for AutoRun and AutoPlay\n")

		restoreKey(keyAutorun, keyAutorunName, "NoDriveTypeAutoRun")
		restoreKey(keyAutorun, keyAutorunName, "NoAutorun")
		restoreKey(keyAutoplay, keyAutoplayName, "DisableAutoplay")
	} else {
		events.AppendText("Hardening by disabling AutoRun and AutoPlay\n")

		saveOriginalRegistryDWORD(keyAutorun, keyAutorunName, "NoDriveTypeAutoRun")
		saveOriginalRegistryDWORD(keyAutorun, keyAutorunName, "NoAutorun")
		saveOriginalRegistryDWORD(keyAutoplay, keyAutoplayName, "DisableAutoplay")

		keyAutorun.SetDWordValue("NoDriveTypeAutoRun", 0xb5)
		keyAutorun.SetDWordValue("NoAutorun", 1)
		keyAutoplay.SetDWordValue("DisableAutoplay", 1)
	}

	keyAutorun.Close()
	keyAutoplay.Close()
}
