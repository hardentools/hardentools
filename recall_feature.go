// Hardentools
// Copyright (C) 2017-2025 Security Without Borders
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

// Enable Recall Feature:
// 	Enable-WindowsOptionalFeature -Online -FeatureName "Recall"
// Disable and Remove Recall Feature:
//  Disable-WindowsOptionalFeature -Online -FeatureName "Recall" -Remove
// Get Status:
//  Get-WindowsOptionalFeature -Online -FeatureName "Recall"
// More details here:
// - https://learn.microsoft.com/en-us/windows/client-management/manage-recall

import (
	"errors"
	"fmt"
	"strings"
)

// RecallStruct ist the struct for HardenInterface implementation.
type RecallStruct struct {
	shortName       string
	longName        string
	description     string
	hardenByDefault bool
}

// Recall contains Names for Recall Feature implementation of hardenInterface.
var Recall = &RecallStruct{
	shortName:       "Recall Windows Feature",
	longName:        "Recall Windows Feature",
	description:     `Recall Windows Feature`,
	hardenByDefault: false,
}

var featureName = "recall"

// TODO: Extensive logging with "Info" log level needs to be reduced after
// beta testing

// Harden method.
func (recall RecallStruct) Harden(harden bool) error {
	psString := ""
	if harden {
		// save state
		if recall.IsHardened() {
			saveHardenState(featureName, "disabled")
		} else {
			saveHardenState(featureName, "enabled")
		}

		// set Powershell-Command
		psString = fmt.Sprintf("Disable-WindowsOptionalFeature -Online -FeatureName \"Recall\" -Remove")
	} else {
		savedState, err := getSavedHardenState(featureName)
		if err != nil {
			// no saved state found, so will not restore
			Info.Println("Recall: No saved state found, so will not restore")
			return nil
		}

		if savedState != "enabled" {
			Info.Println("Recall: Was not in enabled state before hardening, so will not restore")
			return nil
		}

		// set Powershell-Command
		psString = fmt.Sprintf("Enable-WindowsOptionalFeature -Online -FeatureName \"Recall\"")
	}

	Info.Printf("Recall: Executing Powershell.exe with command \"%s\"", psString)
	out, err := executeCommand("PowerShell.exe", "-noprofile", "-Command", psString)
	if err != nil {
		Info.Printf("ERROR: Recall: Executing Powershell.exe with command \"%s\" failed", psString)
		Info.Printf("ERROR: Recall: Powershell Output was: %s", out)
		return errors.New("Recall Feature system call failed")
	}

	isHardened := recall.IsHardened()
	if harden {
		if !isHardened {
			Info.Print("Recall: Hardening seems to have failed")
			showInfoDialog("Recall has not been disabled!")
			return errors.New("Recall has not been disabled")
		}
	} else {
		if isHardened {
			Info.Print("Recall: Reenabling seems to have failed")
			showInfoDialog("Recall has not been enabled!")
			return errors.New("Recall has not been enabled")
		}
		// Delete savedState in hardentools registry key
		deleteSavedHardenState(featureName)
	}

	Info.Println("Recall: Process successfull")
	return nil
}

// IsHardened checks if Recall is already hardened.
func (recall RecallStruct) IsHardened() bool {
	psStringTest := "Get-WindowsOptionalFeature -Online -FeatureName \"Recall\" | Select-Object -ExpandProperty State"
	Info.Printf("Recall: Executing Powershell.exe with command \"%s\"", psStringTest)
	out, err := executeCommand("PowerShell.exe", "-noprofile", "-Command", psStringTest)
	if err != nil {
		Info.Printf("ERROR: Recall: Executing Powershell.exe with command \"%s\" failed", psStringTest)
		Info.Printf("ERROR: Recall: Powershell Output was: %s", out)
		return false
	}

	Info.Printf("Recall: Powershell output for test of status was:\n%s", out)
	out = strings.ReplaceAll(out, "\r\n", "")
	// Output should start with "Disabled", e.g. it should be "DisabledWithPayloadRemoved"
	if strings.HasPrefix(out, "Disabled") {
		Info.Print("Recall: Is hardened")
		return true
	}
	Info.Print("Recall: Not hardened")
	return false
}

// Name returns Name.
func (recall RecallStruct) Name() string {
	return recall.shortName
}

// LongName returns Long Name.
func (recall RecallStruct) LongName() string {
	return recall.longName
}

// Description returns description.
func (recall RecallStruct) Description() string {
	return recall.description
}

// HardenByDefault returns if subject should be hardened by default.
func (recall RecallStruct) HardenByDefault() bool {
	return recall.hardenByDefault
}
