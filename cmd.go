// Hardentools
// Copyright (C) 2017-2020 Security Without Borders
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

// CmdDisallowRunMembers is the struct for the HardenInterface implementation.
type CmdDisallowRunMembers struct {
	shortName       string
	longName        string
	description     string
	hardenByDefault bool
}

// Cmd is the struct for hardentools interface that combines registry keys
// and CmdDisallowRunMembers.
var Cmd = &MultiHardenInterfaces{
	shortName:       "Disable cmd.exe",
	longName:        "Disable cmd.exe",
	description:     "Disables cmd.exe",
	hardenByDefault: false,
	hardenInterfaces: []HardenInterface{
		CmdDisallowRunMembers{
			"CmdDisallowRunMembers",
			"CmdDisallowRunMembers",
			"CmdDisallowRunMembers",
			false,
		},
	},
}

// Harden disables cmd.exe.
//  [HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer]
//  "DisallowRun"=dword:00000001
//  [HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun]
//  "3"="cmd.exe"
func (cmd CmdDisallowRunMembers) Harden(harden bool) error {
	if harden == false {
		// Restore.

		// Open DisallowRun key.
		keyDisallow, err := registry.OpenKey(registry.CURRENT_USER, explorerDisallowRunKey, registry.ALL_ACCESS)
		if err != nil {
			return errors.New("OpenKey to restore cmd failed")
		}
		defer keyDisallow.Close()

		// Delete values for disallowed executables (by iterating all existing values).
		// NOTE: This implementation currently also deletes values that
		//       were not created by hardentools if they are equivalent
		//       with the hardentools created ones (it has to be decided
		//       if this is a bug or a feature.
		for i := 1; true; i++ {
			value, _, err := keyDisallow.GetStringValue(strconv.Itoa(i))
			if err != nil {
				// Stop for loop if end of list reached.
				break
			}

			switch value {
			case "cmd.exe":
				err := keyDisallow.DeleteValue(strconv.Itoa(i))
				if err != nil {
					return fmt.Errorf("Could not restore %s by deleting corresponding registry value due to error: %s",
						value, err.Error())
				}
				Trace.Printf("Restored %s by deleting corresponding registry value", value)
			}
		}

		// Repair order for value entries in DisallowRun key.
		leftDisallowRunValues := 0
		values, err := keyDisallow.ReadValueNames(-1)
		if err != nil {
			Info.Printf(err.Error())
		} else {
			newValues := make(map[int]string)

			for i, value := range values {
				// Get old value name and data content.
				content, _, err := keyDisallow.GetStringValue(value)
				if err != nil {
					break
				}
				Trace.Printf(value + "=" + content)

				// Saving data.
				newValues[i+1] = content

				// Delete old value.
				err = keyDisallow.DeleteValue(value)
				if err != nil {
					Info.Printf(err.Error())
					return errors.New(errorRestoreDisallowRunFailed)
				}
			}
			// Create new values according to index (i).
			for key, val := range newValues {
				err := keyDisallow.SetStringValue(strconv.Itoa(key), val)
				if err != nil {
					Info.Printf(err.Error())
					return errors.New(errorRestoreDisallowRunFailed)
				}
			}

			// Save number of values left over after cleanup.
			leftDisallowRunValues = len(newValues)
		}
		keyDisallow.Close()

		if leftDisallowRunValues == 0 {
			// Delete DisallowRun key if there are values left, otherwise keep it.
			err := registry.DeleteKey(registry.CURRENT_USER, explorerDisallowRunKey)
			if err != nil {
				Info.Printf(err.Error())
				return errors.New(errorRestoreDisallowRunFailed)
			}

			keyExplorer, err := registry.OpenKey(registry.CURRENT_USER, explorerPoliciesKey, registry.ALL_ACCESS)
			if err != nil {
				Info.Printf(err.Error())
				return errors.New(errorRestoreDisallowRunFailed)
			}
			defer keyExplorer.Close()

			err = keyExplorer.DeleteValue("DisallowRun")
			if err != nil {
				Info.Printf(err.Error())
				return errors.New(errorRestoreDisallowRunFailed)
			}
		}
	} else {
		// Harden.

		////
		// Create or Open DisallowRun key.
		keyDisallow, _, err := registry.CreateKey(registry.CURRENT_USER, explorerDisallowRunKey, registry.ALL_ACCESS)
		if err != nil {
			return errors.New("CreateKey to disable cmd.exe failed")
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
			return errors.New("Could not disable cmd.exe due to error " + err.Error())
		}

		////
		// Create or modify DisallowRun value
		keyExplorer, err := registry.OpenKey(registry.CURRENT_USER, explorerPoliciesKey, registry.ALL_ACCESS)
		if err != nil {
			Info.Printf(err.Error())
			return errors.New("Could not disable cmd.exe due to error " + err.Error())
		}
		defer keyExplorer.Close()

		err = keyExplorer.SetDWordValue("DisallowRun", 0x01)
		if err != nil {
			Info.Printf(err.Error())
			return errors.New("Could not disable cmd.exe due to error " + err.Error())
		}
	}

	return nil
}

// IsHardened verifies if harden object of type CmdDisallowRunMembers is already hardened
func (cmd CmdDisallowRunMembers) IsHardened() bool {
	var (
		cmdExeFound = false
	)

	keyDisallow, err := registry.OpenKey(registry.CURRENT_USER, explorerDisallowRunKey, registry.READ)
	if err != nil {
		Trace.Printf("IsHardened(): Could not open DisallowRun registry key due to error %s", err.Error())
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
