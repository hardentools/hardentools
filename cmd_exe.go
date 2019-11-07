// Hardentools
// Copyright (C) 2019  Security Without Borders
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
	"fmt"
	"strconv"

	"golang.org/x/sys/windows/registry"
)

// CmdDisallowRunMembers is the struct for the HardenInterface implementation
type CmdDisallowRunMembers struct {
	shortName       string
	longName        string
	description     string
	hardenByDefault bool
}

// Cmd is the struct for hardentools interface that combines registry keys and CmdDisallowRunMembers
var Cmd = &MultiHardenInterfaces{
	shortName:       "cmd.exe",
	longName:        "Disable cmd.exe",
	description:     "Disables cmd.exe",
	hardenByDefault: false,
	hardenInterfaces: []HardenInterface{
		CmdDisallowRunMembers{"CmdDisallowRunMembers", "CmdDisallowRunMembers", "CmdDisallowRunMembers", false},
		// &RegistrySingleValueDWORD{
		// 	RootKey:       registry.CURRENT_USER,
		// 	Path:          "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer",
		// 	ValueName:     "DisallowRun",
		// 	HardenedValue: 0x1,
		// 	shortName:     "Cmd_DisallowRun"},
	},
}

// Harden disables cmd.exe
//  [HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer]
//  "DisallowRun"=dword:00000001
//  [HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun]
//  "3"="cmd.exe"
func (cmd CmdDisallowRunMembers) Harden(harden bool) error {
	if harden == false {
		// Restore.

		// delete values for disallowed executables (by iterating all existing values)
		// TODO: This only works if the hardentools values are the last
		//       ones (if values are deleted and numbers are not in
		//       consecutive order anymore, that might lead to Explorer
		//       ignoring entries - to be tested
		// TODO: This implementation currently also deletes values that
		//       were not created by hardentools if they are equivalent
		//       with the hardentools created ones (it has to be decided
		//       if this is a bug or a feature

		// Open DisallowRun key.
		keyDisallow, err := registry.OpenKey(registry.CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\DisallowRun", registry.ALL_ACCESS)
		if err != nil {
			return errors.New("\n!! OpenKey to enable cmd failed")
		}
		defer keyDisallow.Close()

		for i := 1; i < 100; i++ {
			value, _, _ := keyDisallow.GetStringValue(strconv.Itoa(i))

			switch value {
			case "cmd.exe":
				err := keyDisallow.DeleteValue(strconv.Itoa(i))
				if err != nil {
					errorText := fmt.Sprintf("Could not restore %s by deleting corresponding registry value due to error: %s", value, err.Error())
					return errors.New(errorText)
				}
				Trace.Printf("Restored %s by deleting corresponding registry value", value)
			}
		}
		keyDisallow.Close()
		// TODO: remove DisallowRun Value if still exists
	} else {
		// Harden.

		// Create or Open DisallowRun key.
		keyDisallow, _, err := registry.CreateKey(registry.CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\DisallowRun", registry.ALL_ACCESS)
		if err != nil {
			return errors.New("\n!! CreateKey to disable cmd.exe failed")
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
		err = keyDisallow.SetStringValue(strconv.Itoa(startingPoint), "cmd.exe")
		if err != nil {
			return errors.New("!! Could not disable cmd.exe due to error " + err.Error())
		}
	}

	return nil
}

// IsHardened verifies if harden object of type CmdDisallowRunMembers is already hardened
func (cmd CmdDisallowRunMembers) IsHardened() bool {
	var (
		cmdExeFound bool = false
	)

	keyDisallow, err := registry.OpenKey(registry.CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\DisallowRun", registry.READ)
	if err != nil {
		Info.Printf("Could not open registry key Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\DisallowRun due to error %s", err.Error())
		return false
	}
	defer keyDisallow.Close()

	for i := 1; i < 100; i++ {
		value, _, _ := keyDisallow.GetStringValue(strconv.Itoa(i))

		switch value {
		case "cmd.exe":
			cmdExeFound = true
		}
	}

	if cmdExeFound {
		return true
	}

	return false
}

// Name returns the (short) name of the harden item
func (cmd CmdDisallowRunMembers) Name() string {
	return cmd.shortName
}

// LongName returns the long name of the harden item
func (cmd CmdDisallowRunMembers) LongName() string {
	return cmd.longName
}

// Description of the harden item
func (cmd CmdDisallowRunMembers) Description() string {
	return cmd.description
}

// HardenByDefault returns if subject should be hardened by default
func (cmd CmdDisallowRunMembers) HardenByDefault() bool {
	return cmd.hardenByDefault
}
