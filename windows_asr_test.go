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
	"fmt"
	"io/ioutil"
	"strings"
	"testing"
)

// func TestWarnIfWindowsDefenderNotActive(t *testing.T) {
// 	warnIfWindowsDefenderNotActive()
// }

// IsHardened checks if ASR is already hardened
func TestIsHardened(t *testing.T) {
	initLogging(ioutil.Discard, ioutil.Discard)

	if !checkWindowsVersion() {
		t.Error("Invalid Windows Version")
	}

	t.Log("--- Get-MpPreference before hardening")
	debugOutput(t)

	err := WindowsASR.Harden(true)
	if err != nil {
		t.Error(err)
	}

	isHardened := WindowsASR.IsHardened()
	if isHardened == false {
		t.Error("Harden did not work correctly")
	}

	t.Log("--- Get-MpPreference after hardening")
	debugOutput(t)

	err = WindowsASR.Harden(false)
	if err != nil {
		t.Error(err)
	}

	isHardened = WindowsASR.IsHardened()
	if isHardened == true {
		t.Error("Restore did not work correctly")
	}

	t.Log("--- Get-MpPreference after restoring")
	debugOutput(t)
}

func debugOutput(t *testing.T) {
	psString := fmt.Sprintf("$prefs = Get-MpPreference; $prefs.AttackSurfaceReductionRules_Ids")
	ruleIDsOut, err := executeCommand("PowerShell.exe", "-Command", psString)
	if err != nil {
		t.Logf("ERROR: WindowsASR: Verify if Windows Defender is running. Executing Powershell.exe with command \"%s\" failed.", psString)
		t.Logf("ERROR: WindowsASR: Powershell Output was: %s", ruleIDsOut)
		t.Error("error executing powershell")
	}

	psString = fmt.Sprintf("$prefs = Get-MpPreference; $prefs.AttackSurfaceReductionRules_Actions")
	ruleActionsOut, err := executeCommand("PowerShell.exe", "-Command", psString)
	if err != nil {
		t.Logf("ERROR: WindowsASR: Verify if Windows Defender is running. Executing Powershell.exe with command \"%s\" failed.", psString)
		t.Logf("ERROR: WindowsASR: Powershell Output was: %s", ruleActionsOut)
		t.Error("error executing powershell")
	}

	// split / remove line feeds and carriage return
	currentRuleIDs := strings.Split(ruleIDsOut, "\r\n")
	currentRuleActions := strings.Split(ruleActionsOut, "\r\n")

	// just some debug output
	for i, ruleIDdebug := range currentRuleIDs {
		if len(ruleIDdebug) > 0 {
			t.Logf("%s = %s\n", ruleIDdebug, currentRuleActions[i])
		}
	}
}
