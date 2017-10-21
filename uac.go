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

func triggerUAC(harden bool) {
	keyName := "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System"
	key, _ := registry.OpenKey(registry.LOCAL_MACHINE, keyName, registry.ALL_ACCESS)
	valueName := "ConsentPromptBehaviorAdmin"

	if harden == false {
		events.AppendText("Restoring original UAC settings\n")
		restoreKey(key, keyName, valueName)
	} else {
		events.AppendText("Hardening by setting UAC to prompt for consent on secure desktops\n")
		var value uint32 = 2

		// save original state to be able to restore it
		saveOriginalRegistryDWORD(key, keyName, valueName)

		// harden
		key.SetDWordValue(valueName, value)
	}

	key.Close()
}
