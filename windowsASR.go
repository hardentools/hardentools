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
	"io"
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
	longName    string
	description string
}

var WindowsASR = &WindowsASRStruct{
	shortName:   "WindowsASR",
	longName:    "Windows ASR (needs Win 10/1709)",
	description: "Windows Attack Surface Reduction (ASR) (needs Win 10/1709)",
}

//// HardenInterface methods

func (asr WindowsASRStruct) Harden(harden bool) error {
	if harden {
		// harden
		fmt.Println("Test")
		if checkWindowsVersion() {
			// TODO: this command seems correct already
			psString := fmt.Sprintf("Set-MpPreference -AttackSurfaceReductionRules_Ids %s -AttackSurfaceReductionRules_Actions %s", ruleIDEnumeration, enabledEnumeration)
			fmt.Println("Executing: PowerShell.exe -Command ", psString)

			// TODO: executing the above command this way doesn't seem to work!"
			_, stdout, stderr, err := StartProcess("PowerShell.exe", "-Command", psString)
			//out, err := exec.Command("PowerShell.exe", "-Command", psString).Output()
			fmt.Println(" stdout = ", stdout)
			//fmt.Println(" stdin = ", stdin)
			fmt.Println(" stderr = ", stderr)
			fmt.Println(" error = ", err)
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
			// TODO
		} else {
			fmt.Println("Not restoring Windows ASR, since Windows it too old (need at least Windows 10 - 1709")
		}
	}

	return nil
}

func (asr WindowsASRStruct) IsHardened() bool {
	var hardened = false

	if checkWindowsVersion() {
		// TODO
	} else {
		fmt.Println("Windows ASR can not be hardened, since Windows it too old (need at least Windows 10 - 1709")
		return false
	}

	return hardened
}

func (asr WindowsASRStruct) Name() string {
	return asr.shortName
}

func (asr WindowsASRStruct) LongName() string {
	return asr.longName
}

func (asr WindowsASRStruct) Description() string {
	return asr.description
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

// from https://github.com/gorillalabs/go-powershell/blob/master/backend/local.go
// MIT Licence:
// Copyright (c) 2017, Gorillalabs
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.
//
// http://www.opensource.org/licenses/MIT
func StartProcess(cmd string, args ...string) (io.Writer, io.Reader, io.Reader, error) {
	command := exec.Command(cmd, args...)

	stdin, err := command.StdinPipe()
	if err != nil {
		return nil, nil, nil, HardenError{"Could not get hold of the PowerShell's stdin stream"}
	}

	stdout, err := command.StdoutPipe()
	if err != nil {
		return nil, nil, nil, HardenError{"Could not get hold of the PowerShell's stdout stream"}
	}

	stderr, err := command.StderrPipe()
	if err != nil {
		return nil, nil, nil, HardenError{"Could not get hold of the PowerShell's stderr stream"}
	}

	err = command.Start()
	if err != nil {
		return nil, nil, nil, HardenError{"Could not spawn PowerShell process"}
	}

	err = command.Wait()

	return stdin, stdout, stderr, err
}
