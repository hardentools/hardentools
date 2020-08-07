// Hardentools
// Copyright (C) 2020  Security Without Borders
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

// PowerShellDisallowRunMembers is the struct for the HardenInterface implementation
type PowerShellDisallowRunMembers struct {
	shortName       string
	longName        string
	description     string
	hardenByDefault bool
}

// PowerShell is the struct for hardentools interface that combines registry keys and PowerShellDisallowRunMembers
var PowerShell = &MultiHardenInterfaces{
	shortName:       "Powershell",
	longName:        "Disable Powershell",
	description:     "Disables Powershell and Powershell ISE",
	hardenByDefault: true,
	hardenInterfaces: []HardenInterface{
		PowerShellDisallowRunMembers{"PowerShell_DisallowRunMembers", "PowerShell_DisallowRunMembers", "PowerShell_DisallowRunMembers", true},
	},
}

// Harden disables Powershell
//  [HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer]
//  "DisallowRun"=dword:00000001
//  [HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun]
//  "1"="powershell_ise.exe"
//  "2"="powershell.exe"
func (pwShell PowerShellDisallowRunMembers) Harden(harden bool) error {

	if harden == false {
		// Restore.

		// Open DisallowRun key.
		keyDisallow, err := registry.OpenKey(registry.CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\DisallowRun", registry.ALL_ACCESS)
		if err != nil {
			return errors.New("OpenKey to enable Powershell failed")
		}
		defer keyDisallow.Close()

		// delete values for disallowed executables (by iterating all existing values)
		// Note: This implementation currently also deletes values that
		//       were not created by hardentools if they are equivalent
		//       with the hardentools created ones (it has to be decided
		//       if this is a bug or a feature
		for i := 1; i < 100; i++ {
			value, _, _ := keyDisallow.GetStringValue(strconv.Itoa(i))

			switch value {
			case "powershell_ise.exe", "powershell.exe":
				err := keyDisallow.DeleteValue(strconv.Itoa(i))
				if err != nil {
					errorText := fmt.Sprintf("Could not restore %s by deleting corresponding registry value due to error: %s", value, err.Error())
					return errors.New(errorText)
				}
				Trace.Printf("Restored %s by deleting corresponding registry value", value)
			}
		}

		// repair order for value entries in DisallowRun key
		leftDisallowRunValues := 0
		values, err := keyDisallow.ReadValueNames(-1)
		if err != nil {
			Info.Printf(err.Error())
		} else {
			newValues := make(map[int]string)

			for i, value := range values {
				// get old value name and data content
				content, _, err := keyDisallow.GetStringValue(value)
				if err != nil {
					break
				}
				Trace.Printf(value + "=" + content)

				// saving data
				newValues[i+1] = content

				// delete old value
				err = keyDisallow.DeleteValue(value)
				if err != nil {
					Info.Printf(err.Error())
					return errors.New("Fully restoring DisableRun settings failed")
				}
			}
			// create new according to index (i)
			for key, val := range newValues {
				err := keyDisallow.SetStringValue(strconv.Itoa(key), val)
				if err != nil {
					Info.Printf(err.Error())
					return errors.New("Fully restoring DisableRun settings failed")
				}
			}

			// save number of values left over after cleanup
			leftDisallowRunValues = len(newValues)
		}

		keyDisallow.Close()

		if leftDisallowRunValues == 0 {
			// delete DisallowRun key if there are values left, otherwise keep it
			err := registry.DeleteKey(registry.CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\DisallowRun")
			if err != nil {
				Info.Printf(err.Error())
				return errors.New("Fully restoring DisableRun settings failed")
			}

			keyExplorer, err := registry.OpenKey(registry.CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer", registry.ALL_ACCESS)
			if err != nil {
				Info.Printf(err.Error())
				return errors.New("Fully restoring DisableRun settings failed")
			}
			defer keyExplorer.Close()

			err = keyExplorer.DeleteValue("DisallowRun")
			if err != nil {
				Info.Printf(err.Error())
				return errors.New("Fully restoring DisableRun settings failed")
			}
		}
	} else {
		// Harden.

		////
		// Create or Open DisallowRun key.
		keyDisallow, _, err := registry.CreateKey(registry.CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\DisallowRun", registry.ALL_ACCESS)
		if err != nil {
			return errors.New("CreateKey to disable powershell failed")
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
		err = keyDisallow.SetStringValue(strconv.Itoa(startingPoint), "powershell_ise.exe")
		if err != nil {
			return errors.New("Could not disable PowerShell ISE due to error " + err.Error())
		}

		err = keyDisallow.SetStringValue(strconv.Itoa(startingPoint+1), "powershell.exe")
		if err != nil {
			return errors.New("Could not disable PowerShell due to error " + err.Error())
		}

		////
		// Create or modify DisallowRun value
		keyExplorer, err := registry.OpenKey(registry.CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer", registry.ALL_ACCESS)
		if err != nil {
			Info.Printf(err.Error())
			return errors.New("Could not disable PowerShell due to error " + err.Error())
		}
		defer keyExplorer.Close()

		err = keyExplorer.SetDWordValue("DisallowRun", 0x01)
		if err != nil {
			Info.Printf(err.Error())
			return errors.New("Could not disable PowerShell due to error " + err.Error())
		}
	}

	return nil
}

// IsHardened verifies if harden object of type PowerShellDisallowRunMembers is already hardened
func (pwShell PowerShellDisallowRunMembers) IsHardened() bool {
	var (
		powerShellIseFound, powerShellFound bool = false, false
	)

	keyDisallow, err := registry.OpenKey(registry.CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\DisallowRun", registry.READ)
	if err != nil {
		Trace.Printf("IsHardened(): Could not open registry key Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\DisallowRun due to error %s", err.Error())
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
		}
	}

	if powerShellIseFound && powerShellFound {
		return true
	}

	return false
}

// Name returns the (short) name of the harden item
func (pwShell PowerShellDisallowRunMembers) Name() string {
	return pwShell.shortName
}

// LongName returns the long name of the harden item
func (pwShell PowerShellDisallowRunMembers) LongName() string {
	return pwShell.longName
}

// Description of the harden item
func (pwShell PowerShellDisallowRunMembers) Description() string {
	return pwShell.description
}

// HardenByDefault returns if subject should be hardened by default
func (pwShell PowerShellDisallowRunMembers) HardenByDefault() bool {
	return pwShell.hardenByDefault
}
