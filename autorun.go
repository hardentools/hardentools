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
	key_autorun, _, _ := registry.CreateKey(registry.CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer", registry.WRITE)
	key_autoplay, _, _ := registry.CreateKey(registry.CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\AutoplayHandlers", registry.WRITE)

	if harden==false {
		events.AppendText("Restoring default by enabling AutoRun and AutoPlay\n")
		
		key_autorun.DeleteValue("NoDriveTypeAutoRun")
		key_autorun.DeleteValue("NoAutorun")
		key_autoplay.DeleteValue("DisableAutoplay")
	} else {
		events.AppendText("Hardening by disabling AutoRun and AutoPlay\n")
		
		key_autorun.SetDWordValue("NoDriveTypeAutoRun", 0xb5)
		key_autorun.SetDWordValue("NoAutorun", 1)
		key_autoplay.SetDWordValue("DisableAutoplay", 1)
	}

	key_autorun.Close()
	key_autoplay.Close()
}
