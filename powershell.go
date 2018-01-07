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
	"errors"
	"strconv"

	"golang.org/x/sys/windows/registry"
)

type PowerShellDisallowRunMembers struct {
	shortName   string
	longName    string
	description string
}

var PowerShell = &MultiHardenInterfaces{
	shortName:   "PowerShell",
	longName:    "Powershell and cmd.exe",
	description: "Disables Powershell, Powershell ISE and cmd.exe",
	hardenInterfaces: []HardenInterface{
		PowerShellDisallowRunMembers{"PowerShell_DisallowRunMembers", "PowerShell_DisallowRunMembers", "PowerShell_DisallowRunMembers"},

		&RegistrySingleValueDWORD{
			RootKey:       registry.CURRENT_USER,
			Path:          "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer",
			ValueName:     "DisallowRun",
			HardenedValue: 0x1,
			shortName:     "PowerShell_DisallowRun"},
	},
}

// Disables Powershell and cmd.exe
//  [HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer]
//  "DisallowRun"=dword:00000001
//  [HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun]
//  "1"="powershell_ise.exe"
//  "2"="powershell.exe"
//  "3"="cmd.exe"
func (pwShell PowerShellDisallowRunMembers) Harden(harden bool) error {
	if harden == false {
		// Restore.
		//events.AppendText("Restoring original settings by enabling Powershell and cmd\n")

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
			return errors.New("!! OpenKey to enable Powershell and cmd failed.\n")
		}
		defer keyDisallow.Close()

		for i := 1; i < 100; i++ {
			value, _, _ := keyDisallow.GetStringValue(strconv.Itoa(i))

			switch value {
			case "powershell_ise.exe", "powershell.exe", "cmd.exe":
				keyDisallow.DeleteValue(strconv.Itoa(i))
			}
		}
	} else {
		// Harden.
		//events.AppendText("Hardening by disabling Powershell and cmd\n")

		// Create or Open DisallowRun key.
		keyDisallow, _, err := registry.CreateKey(registry.CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\DisallowRun", registry.ALL_ACCESS)
		if err != nil {
			return errors.New("!! CreateKey to disable powershell failed.\n")
		}
		defer keyDisallow.Close()

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
	}

	return nil
}

func (pwShell PowerShellDisallowRunMembers) IsHardened() bool {
	var (
		powerShellIseFound, powerShellFound, cmdExeFound bool = false, false, false
	)

	keyDisallow, err := registry.OpenKey(registry.CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\DisallowRun", registry.READ)
	if err != nil {
		return false
	}
	defer keyDisallow.Close()

	for i := 1; i < 100; i++ {
		value, _, _ := keyDisallow.GetStringValue(strconv.Itoa(i))

		switch value {
		case "powershell_ise.exe":
			powerShellIseFound = true
		case "powershell.exe":
			powerShellFound = true
		case "cmd.exe":
			cmdExeFound = true
		}
	}

	if powerShellIseFound && powerShellFound && cmdExeFound {
		return true
	}

	return false
}

func (pwShell PowerShellDisallowRunMembers) Name() string {
	return pwShell.shortName
}

func (pwShell PowerShellDisallowRunMembers) LongName() string {
	return pwShell.longName
}

func (pwShell PowerShellDisallowRunMembers) Description() string {
	return pwShell.description
}
