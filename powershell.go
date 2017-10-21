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

// Disables Powershell and cmd.exe
//  [HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer]
//  "DisallowRun"=dword:00000001
//  [HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun]
//  "1"="powershell_ise.exe"
//  "2"="powershell.exe"
//  "3"="cmd.exe"

func triggerPowerShell(harden bool) {
	keyExplorerName := "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer"
	keyExplorer, _, _ := registry.CreateKey(registry.CURRENT_USER, keyExplorerName, registry.ALL_ACCESS)
	hardentoolsKey, _, _ := registry.CreateKey(registry.CURRENT_USER, hardentoolsKeyPath, registry.ALL_ACCESS)

	if harden == false {
		events.AppendText("Restoring original settings by enabling Powershell and cmd\n")

		// Set DisallowRun to old value / delete if no old value saved.
		restoreKey(keyExplorer, keyExplorerName, "DisallowRun")

		// delete values for disallowed executables (by iterating all existing values)
		// TODO: This only works if the hardentools values are the last
		//       ones (if values are deleted and numbers are not in
		//       consecutive order anymore, that might lead to Explorer
		//       ignoring entries - to be tested
		// TODO: This implementation currently also deletes values that
		//       were not created by hardentools if they are equivalent
		//       with the hardentools created ones (it has to be decided
		//       if this is a bug or a feature

		keyDisallow, err := registry.OpenKey(registry.CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\DisallowRun", registry.ALL_ACCESS)
		if err != nil {
			events.AppendText("!! OpenKey to enable Powershell and cmd failed.\n")
		}

		for i := 1; i < 100; i++ {
			value, _, _ := keyDisallow.GetStringValue(strconv.Itoa(i))

			switch value {
			case "powershell_ise.exe", "powershell.exe", "cmd.exe":
				keyDisallow.DeleteValue(strconv.Itoa(i))
			}
		}

		keyDisallow.Close()
	} else {
		events.AppendText("Hardening by disabling Powershell and cmd\n")

		// Save original state of "DisallowRun" value to be able to restore it.
		saveOriginalRegistryDWORD(keyExplorer, keyExplorerName, "DisallowRun")

		// Create DisallowRun key.
		keyDisallow, _, err := registry.CreateKey(registry.CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\DisallowRun", registry.ALL_ACCESS)
		if err != nil {
			events.AppendText("!! CreateKey to disable powershell failed.\n")
		}

		// Enable DisallowRun.
		keyExplorer.SetDWordValue("DisallowRun", 0x1)

		// Find starting point (only relevant if there are existing entries)
		startingPoint := 1
		for i := 1; i < 100; i++ {
			startingPoint = i
			_, _, err = keyDisallow.GetStringValue(strconv.Itoa(startingPoint))
			if err != nil {
				break
			}
		}

		// Set values.
		keyDisallow.SetStringValue(strconv.Itoa(startingPoint), "powershell_ise.exe")
		keyDisallow.SetStringValue(strconv.Itoa(startingPoint+1), "powershell.exe")
		keyDisallow.SetStringValue(strconv.Itoa(startingPoint+2), "cmd.exe")

		keyDisallow.Close()
	}

	keyExplorer.Close()
	hardentoolsKey.Close()
}
