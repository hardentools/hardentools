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
	key, _ := registry.OpenKey(registry.LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", registry.WRITE)

	if harden==false {
		events.AppendText("Restoring default by restoring UAC to default settings\n")
		
		err := key.SetDWordValue("ConsentPromptBehaviorAdmin", 5)
		if err != nil {
			events.AppendText("!! SetDWordValue on UAC failed.\n")
		}
	} else {
		events.AppendText("Hardening by setting UAC to prompt for consent on secure desktops\n")
		
		err := key.SetDWordValue("ConsentPromptBehaviorAdmin", 2)
		if err != nil {
			events.AppendText("!! SetDWordValue on UAC failed.\n")
		}
	}

	key.Close()
}
