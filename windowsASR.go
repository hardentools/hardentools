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

//# https://docs.microsoft.com/en-us/windows/threat-protection/windows-defender-exploit-guard/attack-surface-reduction-exploit-guard
//# https://docs.microsoft.com/en-us/windows/threat-protection/windows-defender-exploit-guard/enable-attack-surface-reduction
//# Set-MpPreference -AttackSurfaceReductionRules_Ids <rule ID 1>,<rule ID 2>,<rule ID 3>,<rule ID 4> -AttackSurfaceReductionRules_Actions Enabled, Enabled, Disabled, AuditMode

import (
	"fmt"
	"golang.org/x/sys/windows/registry"
	"os/exec"
	"strings"
)

const ruleIDEnumeration =
//Block executable content from email client and webmail
"BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550," +
	//Block Office applications from creating child processes
	"D4F940AB-401B-4EFC-AADC-AD5F3C50688A," +
	// Block Office applications from creating executable content
	"3B576869-A4EC-4529-8536-B80A7769E899," +
	// Block Office applications from injecting code into other processes
	"75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84," +
	// Block JavaScript or VBScript from launching downloaded executable content
	"D3E037E1-3EB8-44C8-A917-57927947596D," +
	// Block execution of potentially obfuscated scripts
	"5BEB7EFE-FD9A-4556-801D-275E5FFC04CC," +
	// Block Win32 API calls from Office macro
	"92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B"
const enabledEnumeration = "Enabled,Enabled,Enabled,Enabled,Enabled,Enabled,Enabled"

// data type for a RegEx Path / Single Value DWORD combination
type WindowsASRStruct struct {
	shortName   string
	displayName string
}

var WindowsASR = &WindowsASRStruct{
	shortName:   "WindowsASR",
	displayName: "Windows ASR (ab Win 10/1709)",
}

//// HardenInterface methods

func (asr WindowsASRStruct) harden(harden bool) error {
	if harden {
		// harden
		fmt.Println("Test")
		if checkWindowsVersion() {
			// TODO: this command seems correct already
			psString := fmt.Sprintf("{Set-MpPreference -AttackSurfaceReductionRules_Ids %s -AttackSurfaceReductionRules_Actions %s}", ruleIDEnumeration, enabledEnumeration)
			fmt.Println("Executing: PowerShell.exe -Command ", psString)

			// TODO: executing the above command this way doesn't seem to work!"
			out, err := exec.Command("PowerShell.exe", "-Command", psString).Output()
			fmt.Println(" output = ", string(out[:]))
			if err != nil {
				fmt.Println("Executing ", psString, " failed")
				return err
			}
		} else {
			fmt.Println("Not hardening Windows ASR, since Windows it too old (need at least Windows 10 - 1709)")
		}
	} else {
		// restore
		if checkWindowsVersion() {

		} else {
			fmt.Println("Not restoring Windows ASR, since Windows it too old (need at least Windows 10 - 1709")
		}
	}

	return nil
}

func (asr WindowsASRStruct) isHardened() bool {
	var hardened = false

	if checkWindowsVersion() {

	} else {
		fmt.Println("Windows ASR can not be hardened, since Windows it too old (need at least Windows 10 - 1709")
		return false
	}

	return hardened
}

func (asr WindowsASRStruct) name() string {
	return asr.shortName
}

func checkWindowsVersion() bool {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", registry.QUERY_VALUE)
	if err != nil {
		return false
	}
	defer k.Close()

	maj, _, err := k.GetIntegerValue("CurrentMajorVersionNumber")
	if err != nil {
		return false
	}
	if maj < 10 {
		return false
	}

	min, _, err := k.GetIntegerValue("CurrentMinorVersionNumber")
	if err != nil {
		return false
	}
	if min < 0 {
		return false
	}

	cb, _, err := k.GetStringValue("CurrentBuild")
	if err != nil {
		return false
	}
	if strings.Compare(cb, "15254") < 0 {
		return false
	}

	return true
}
