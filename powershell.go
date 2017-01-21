/*
   Hardentools
   Copyright (C) 2017  Claudio Guarnieri, Mariano Graziano

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

package main

import (
	"golang.org/x/sys/windows/registry"
)

/*
 * Disables Powershell and cmd.exe
 * [HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer]
 * "DisallowRun"=dword:00000001
 * [HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun]
 * "1"="powershell_ise.exe"
 * "2"="powershell.exe"
 * "3"="cmd.exe"
 */
func trigger_powershell(enable bool) {
	key, _, _ := registry.CreateKey(registry.CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer", registry.WRITE)
	if enable {
		events.AppendText("* Enabling Powershell and cmd\n")
		key.DeleteValue("DisallowRun")
	} else {
		events.AppendText("* Disabling Powershell and cmd\ns")
		key2, _, err := registry.CreateKey(registry.CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\DisallowRun", registry.WRITE)
		if err != nil {
			events.AppendText("** CreateKey to disable powershell failed: ")
			panic(err)
		}

		key.SetDWordValue("DisallowRun", 0x1)
		key2.SetStringValue("1", "powershell_ise.exe")
		key2.SetStringValue("2", "powershell.exe")
		key2.SetStringValue("3", "cmd.exe")
		key2.Close()
	}
	key.Close()
}
