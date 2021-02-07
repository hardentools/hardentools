// Hardentools
// Copyright (C) 2017-2021 Security Without Borders
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

// Windows Defender Attack Surface Reduction (ASR) rules.
// Need the following prerequisites to work:
// - Windows 10 >= 1709
// - Endpoints are using Windows Defender Antivirus as the sole antivirus protection app.
// - Using any other antivirus app will cause Windows Defender AV to disable itself.
// - Real-time protection is enabled.
// - Cloud protection is enabled (needed for some of the ASR rules only)
// More details here:
// - https://docs.microsoft.com/en-us/windows/threat-protection/windows-defender-exploit-guard/attack-surface-reduction-exploit-guard
// - https://docs.microsoft.com/en-us/windows/threat-protection/windows-defender-exploit-guard/enable-attack-surface-reduction
// - https://docs.microsoft.com/en-us/windows/threat-protection/windows-defender-exploit-guard/evaluate-attack-surface-reduction

import (
	"errors"
	"fmt"
	"strings"

	"golang.org/x/sys/windows/registry"
)

var ruleIDArray = []string{
	"BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550", // Block executable content from email client and webmail.
	"D4F940AB-401B-4EFC-AADC-AD5F3C50688A", // Block Office applications from creating child processes.
	"3B576869-A4EC-4529-8536-B80A7769E899", // Block Office applications from creating executable content.
	"75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84", // Block Office applications from injecting code into other processes.
	"D3E037E1-3EB8-44C8-A917-57927947596D", // Block JavaScript or VBScript from launching downloaded executable content.
	"5BEB7EFE-FD9A-4556-801D-275E5FFC04CC", // Block execution of potentially obfuscated scripts.
	"92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B", // Block Win32 API calls from Office macro.

	// Leaving the following out for now, since it also blocks hardentools
	// and perhaps also other "not well known to Microsoft" tools.
	// "01443614-CD74-433A-B99E-2ECDC07BFC25", // Block executable files from running unless they meet a prevalence, age, or trusted list criterion.

	"B2B3F03D-6A65-4F7B-A9C7-1C7EF74A9BA4", // Block untrusted and unsigned processes that run from USB.
	"C1DB55AB-C21A-4637-BB3F-A12568109D35", // Use advanced protection against ransomware.
	"D1E49AAC-8F56-4280-B9BA-993A6D77406C", // Block process creations originating from PSExec and WMI commands.
	"26190899-1602-49e8-8b27-eb1d0a1ce869", // Block Office communication application from creating child processes.
	"7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c", // Block Adobe Reader from creating child processes.
	"e6db77e5-3df2-4cf1-b95a-636979351e5b", // Block persistence through WMI event subscription.
	"9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2"} // Block credential stealing from the Windows local security authority subsystem.

var actionsArrayHardended = []bool{true, true, true, true, true, true, true,
	true, true, true, true, true, true, true, true}
var actionsArrayNotHardended = []bool{false, false, false, false, false, false,
	false, false, false, false, false, false, false, false, false}

// WindowsASRStruct ist the struct for HardenInterface implementation.
type WindowsASRStruct struct {
	shortName       string
	longName        string
	description     string
	hardenByDefault bool
}

// WindowsASR contains Names for Windows ASR implementation of hardenInterface.
var WindowsASR = &WindowsASRStruct{
	shortName:       "Windows ASR rules",
	longName:        "Windows ASR rules",
	description:     "Windows Attack Surface Reduction (ASR) rules",
	hardenByDefault: true,
}

// Harden method.
func (asr WindowsASRStruct) Harden(harden bool) error {
	if harden {
		// Harden only if we have at least Windows 10 - 1709.
		if checkWindowsVersion() {
			// TODO: Save original state and restore on restore.

			// Show notification if Windows Defender ist not activated and
			// Cloud Protection is not enabled?
			warnIfWindowsDefenderNotActive()

			// Set the settings for AttackSurfaceReduction using Add-MpPreference.
			for i, ruleID := range ruleIDArray {
				err := AddMPPreference(ruleID, actionsArrayHardended[i])
				if err != nil {
					return err
				}
			}
		} else {
			Info.Println("Windows ASR not activated, since it needs at least Windows 10 - 1709")
		}
	} else {
		// Restore (but only if we have at least Windows 10 - 1709).
		if checkWindowsVersion() {
			// Set the settings for AttackSurfaceReduction using Add-MpPreference.
			for i, ruleID := range ruleIDArray {
				err := AddMPPreference(ruleID, actionsArrayNotHardended[i])
				if err != nil {
					return err
				}
			}
		}
	}

	return nil
}

// IsHardened checks if ASR is already hardened.
func (asr WindowsASRStruct) IsHardened() bool {
	if !checkWindowsVersion() {
		return false
	}

	psString := fmt.Sprintf("$prefs = Get-MpPreference; $prefs.AttackSurfaceReductionRules_Ids")
	ruleIDsOut, err := executeCommand("PowerShell.exe", "-Command", psString)
	if err != nil {
		Info.Printf("ERROR: WindowsASR: Verify if Windows Defender is running. Executing Powershell.exe with command \"%s\" failed.", psString)
		Info.Printf("ERROR: WindowsASR: Powershell Output was: %s", ruleIDsOut)
		// In case command does not work we assume we are not hardened.
		return false
	}

	psString = fmt.Sprintf("$prefs = Get-MpPreference; $prefs.AttackSurfaceReductionRules_Actions")
	ruleActionsOut, err := executeCommand("PowerShell.exe", "-Command", psString)
	if err != nil {
		Info.Printf("ERROR: WindowsASR: Verify if Windows Defender is running. Executing Powershell.exe with command \"%s\" failed.", psString)
		Info.Printf("ERROR: WindowsASR: Powershell Output was: %s", ruleActionsOut)
		// In case command does not work we assume we are not hardened.
		return false
	}

	// Verify if all relevant ruleIDs are there.
	// Split/remove line feeds and carriage return.
	currentRuleIDs := strings.Split(ruleIDsOut, "\r\n")
	currentRuleActions := strings.Split(ruleActionsOut, "\r\n")

	for i, ruleIDdebug := range currentRuleIDs {
		if len(ruleIDdebug) > 0 {
			Trace.Printf("ruleID %d = %s with action = %s\n", i, ruleIDdebug, currentRuleActions[i])
		}
	}

	// Compare to hardened state.
	for i, ruleIDHardened := range ruleIDArray {
		// Check if rule exists by iterating over all ruleIDs.
		var existsAndEqual = false

		for j, currentRuleID := range currentRuleIDs {
			if strings.ToLower(ruleIDHardened) == strings.ToLower(currentRuleID) {
				// Verify if setting is enabled.
				if currentRuleActions[j] == "1" && actionsArrayHardended[i] == true {
					// Everything is fine.
					existsAndEqual = true
				} else {
					return false
				}
			}
		}

		if existsAndEqual == false {
			return false
		}
	}

	// It seems all relevant hardening is in place.
	return true
}

// AddMPPreference sets a ASR rule using Add-MpPreference.
func AddMPPreference(ruleID string, enabled bool) error {
	// Example: Add-MpPreference -AttackSurfaceReductionRules_Ids
	//   75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84
	//   -AttackSurfaceReductionRules_Actions Enabled
	var action string
	if enabled {
		action = "Enabled"
	} else {
		action = "Disabled"
	}
	psString := fmt.Sprintf("Add-MpPreference -AttackSurfaceReductionRules_Ids %s -AttackSurfaceReductionRules_Actions %s", ruleID, action)
	Trace.Printf("WindowsASR: Executing Powershell.exe with command \"%s\"", psString)
	out, err := executeCommand("PowerShell.exe", "-Command", psString)
	if err != nil {
		Info.Printf("ERROR: WindowsASR: Verify if Windows Defender is running. Executing Powershell.exe with command \"%s\" failed. ", psString)
		Info.Printf("ERROR: WindowsASR: Powershell Output was: %s", out)
		return errors.New("Executing powershell cmdlet Add-MpPreference failed (" + ruleID + " = " + action + ")")
	}
	Trace.Printf("WindowsASR: Powershell output was:\n%s", out)
	return nil
}

// Name returns Name.
func (asr WindowsASRStruct) Name() string {
	return asr.shortName
}

// LongName returns Long Name.
func (asr WindowsASRStruct) LongName() string {
	return asr.longName
}

// Description returns description.
func (asr WindowsASRStruct) Description() string {
	return asr.description
}

// HardenByDefault returns if subject should be hardened by default.
func (asr WindowsASRStruct) HardenByDefault() bool {
	return asr.hardenByDefault
}

// checkWindowsVersion checks if hardentools is running on Windows 10 with
// Patch Level >= 1709.
func checkWindowsVersion() bool {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE,
		"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
		registry.QUERY_VALUE)
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

// warnIfWindowsDefenderNotActive shows a notification if Windows Defender
// settings might prevent ASR rules from working.
func warnIfWindowsDefenderNotActive() {
	// Cloud Protection.
	{
		command := "(Get-MpPreference).MAPSReporting"
		expectedValue := "2"
		out, err := executeCommand("PowerShell.exe", "-Command", command)
		if err != nil {
			Info.Printf("Could not verify if Windows Defender Cloud Protection is enabled due to error accessing registry")
			return
		}

		out = strings.ReplaceAll(out, "\r\n", "")
		if out != expectedValue {
			// show notification
			showInfoDialog("Windows Defender Cloud Protection  is not enabled.\nSome ASR rules won't work.")
		}
	}

	// Real-time protection.
	{
		command := "(Get-MpPreference).DisableRealtimeMonitoring"
		expectedValue := "False"
		out, err := executeCommand("PowerShell.exe", "-Command", command)
		if err != nil {
			Info.Printf("Could not verify if Windows Defender Cloud Protection is enabled due to error accessing registry")
			return
		}

		out = strings.ReplaceAll(out, "\r\n", "")

		if out != expectedValue {
			showInfoDialog("Windows Defender Realtime Protection is not enabled.\nASR rules won't work.")
		}
	}
}
