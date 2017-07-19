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

/*
- HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer!NoDriveTypeAutoRun
- HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer!NoAutorun
- HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers!DisableAutoplay 1
*/
func trigger_autorun(harden bool) {
	var key_autorun_name = "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer"
	key_autorun, _, _ := registry.CreateKey(registry.CURRENT_USER, key_autorun_name, registry.ALL_ACCESS)
	var key_autoplay_name = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\AutoplayHandlers"
	key_autoplay, _, _ := registry.CreateKey(registry.CURRENT_USER, key_autoplay_name, registry.ALL_ACCESS)

	if harden == false {
		events.AppendText("Restoring original settings for AutoRun and AutoPlay\n")

		restore_key(key_autorun, key_autorun_name, "NoDriveTypeAutoRun")
		restore_key(key_autorun, key_autorun_name, "NoAutorun")
		restore_key(key_autoplay, key_autoplay_name, "DisableAutoplay")
	} else {
		events.AppendText("Hardening by disabling AutoRun and AutoPlay\n")

		// save original state to be able to restore it
		save_original_registry_DWORD(key_autorun, key_autorun_name, "NoDriveTypeAutoRun")
		save_original_registry_DWORD(key_autorun, key_autorun_name, "NoAutorun")
		save_original_registry_DWORD(key_autoplay, key_autoplay_name, "DisableAutoplay")

		key_autorun.SetDWordValue("NoDriveTypeAutoRun", 0xb5)
		key_autorun.SetDWordValue("NoAutorun", 1)
		key_autoplay.SetDWordValue("DisableAutoplay", 1)
	}

	key_autorun.Close()
	key_autoplay.Close()
}
