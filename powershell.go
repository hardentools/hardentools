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
	"strconv"
)

/*
Disables Powershell and cmd.exe
 [HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer]
 "DisallowRun"=dword:00000001
 [HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun]
 "1"="powershell_ise.exe"
 "2"="powershell.exe"
 "3"="cmd.exe"
*/
func trigger_powershell(harden bool) {
	key_explorer, _, _ := registry.CreateKey(registry.CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer", registry.ALL_ACCESS)
	hardentools_key, _, _ := registry.CreateKey(registry.CURRENT_USER, harden_key_path, registry.ALL_ACCESS)

	// enable
	if harden==false {
		events.AppendText("Restoring original setting by enabling Powershell and cmd\n")

		// set DisallowRun to old value / delete if no old value saved
		saved_state, _, err_sst := hardentools_key.GetIntegerValue("SavedStateDisallowRun")
		if err_sst == nil {
			err := key_explorer.SetDWordValue("DisallowRun", uint32(saved_state))
			if err != nil {
				events.AppendText("!! SetValue to enable Powershell and cmd failed.\n")
			}
		} else {
			err := key_explorer.DeleteValue("DisallowRun")
			if err != nil {
				events.AppendText("!! DeleteValue to enable Powershell and cmd failed.\n")
			}
		}

		// delete values for disallowed executables (by iterating all existing values)
		// TODO: This only works if the hardentools values are the last
		//       ones (if values are deleted and numbers are not in
		//       consecutive order anymore, that might lead to Explorer
		//       ignoring entries - to be tested
		// TODO: This implementation currently also deletes values that
		//       were not created by hardentools if they are equivalent
		//       with the hardentools created ones (it has to be decided
		//       if this is a bug or a feature
		key_disallow, err := registry.OpenKey(registry.CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\DisallowRun", registry.ALL_ACCESS)
		if err != nil {
			events.AppendText("!! OpenKey to enable Powershell and cmd failed.\n")
		}
		for i := 1; i < 100; i++ {
			value, _, _ := key_disallow.GetStringValue(strconv.Itoa(i))
			switch value {
			case "powershell_ise.exe", "powershell.exe", "cmd.exe":
				key_disallow.DeleteValue(strconv.Itoa(i))
			}
		}
		key_disallow.Close()

		hardentools_key.DeleteValue("SavedStateDisallowRun")
	} else {
		events.AppendText("Hardening by disabling Powershell and cmd\n")

		// handle current state (save if not default, to be able to restore former state)
		current_state, _, err_cs := key_explorer.GetIntegerValue("DisallowRun")
		if err_cs != nil {
			// no need to save state
			//events.AppendText("Error reading DisallowRun value\n")
		} else {
			// save state
			hardentools_key.SetDWordValue("SavedStateDisallowRun", uint32(current_state))
		}

		// create DisallowRun key
		key_disallow, _, err := registry.CreateKey(registry.CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\DisallowRun", registry.ALL_ACCESS)
		if err != nil {
			events.AppendText("!! CreateKey to disable powershell failed.\n")
		}

		// enable DisallowRun
		key_explorer.SetDWordValue("DisallowRun", 0x1)

		//// set values for disallowed executables
		// find starting point (only relevant if there are existing entries)
		starting_point := 1
		for i := 1; i < 100; i++ {
			starting_point = i
			_, _, err_sp := key_disallow.GetStringValue(strconv.Itoa(starting_point))
			if err_sp != nil {
				break
			}
		}
		// set values
		key_disallow.SetStringValue(strconv.Itoa(starting_point), "powershell_ise.exe")
		key_disallow.SetStringValue(strconv.Itoa(starting_point+1), "powershell.exe")
		key_disallow.SetStringValue(strconv.Itoa(starting_point+2), "cmd.exe")

		key_disallow.Close()
	}

	key_explorer.Close()
	hardentools_key.Close()
}
