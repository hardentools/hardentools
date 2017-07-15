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

func trigger_uac(harden bool) {
	key_name := "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System"
	key, _ := registry.OpenKey(registry.LOCAL_MACHINE, key_name, registry.ALL_ACCESS)
	value_name := "ConsentPromptBehaviorAdmin"

	if harden == false {
		events.AppendText("Restoring original UAC settings\n")
		restore_key(key, key_name, value_name)
	} else {
		events.AppendText("Hardening by setting UAC to prompt for consent on secure desktops\n")
		var value uint32 = 2

		// save original state to be able to restore it
		save_original_registry_DWORD(key, key_name, value_name)

		// harden
		key.SetDWordValue(value_name, value)
	}

	key.Close()
}
