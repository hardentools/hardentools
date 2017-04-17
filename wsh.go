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

func trigger_wsh(harden bool) {
	key, _, _ := registry.CreateKey(registry.CURRENT_USER, "SOFTWARE\\Microsoft\\Windows Script Host\\Settings", registry.WRITE)

	if harden==false {
		events.AppendText("Restoring default by enabling Windows Script Host\n")
		key.DeleteValue("Enabled")
	} else {
		events.AppendText("Hardening by disabling Windows Script Host\n")
		key.SetDWordValue("Enabled", 0)
	}

	key.Close()
}
