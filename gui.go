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

/*
// some C code for managing elevated privileges
#include <windows.h>
#include <shellapi.h>

// Checks if we are running with elevated privileges (admin rights).
int IsElevated( ) {
    boolean fRet = FALSE;
    HANDLE hToken = NULL;
    if( OpenProcessToken( GetCurrentProcess( ),TOKEN_QUERY,&hToken ) ) {
        TOKEN_ELEVATION Elevation;
        DWORD cbSize = sizeof( TOKEN_ELEVATION );
        if( GetTokenInformation( hToken, TokenElevation, &Elevation, sizeof( Elevation ), &cbSize ) ) {
            fRet = Elevation.TokenIsElevated;
        }
    }
    if( hToken ) {
        CloseHandle( hToken );
    }
    if( fRet ){
		return 1;
	}
	else {
		return 0;
	}
}

// Executes the executable in the current directory (or in path) with "runas"
// to aquire admin privileges.
int ExecuteWithRunas(char execName[]){
	SHELLEXECUTEINFO shExecInfo;

	shExecInfo.cbSize = sizeof(SHELLEXECUTEINFO);

	shExecInfo.fMask = 0x00008000;
	shExecInfo.hwnd = NULL;
	shExecInfo.lpVerb = "runas";
	shExecInfo.lpFile = execName;
	shExecInfo.lpParameters = NULL;
	shExecInfo.lpDirectory = NULL;
	shExecInfo.nShow = SW_NORMAL;
	shExecInfo.hInstApp = NULL;

	boolean success = ShellExecuteEx(&shExecInfo);
	if (success)
		return 1;
	else
		return 0;
}
*/
import "C"

import (
	"errors"
	"fmt"
	"os"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
)

var messageBox, firstColumn, secondColumn, thirdColumn *fyne.Container
var eventsTextAreaProgressBar *widget.ProgressBarInfinite
var stateLabels map[string]*widget.Label
var inProgressLabel *widget.Label

func mainGUI() {
	// Check if hardentools has been started with elevated rights. If not
	// ask user if she wants to elevate.
	if C.IsElevated() == 0 {
		// Main window must already be open for this dialog to work.
		askElevationDialog()
	}
	elevationStatus := false
	if C.IsElevated() == 1 {
		elevationStatus = true
	}

	// Show splash screen since loading takes some time (at least with admin
	// privileges) due to sequential reading of all the settings.
	showSplash()

	// Show main screen.
	createMainGUIContent(elevationStatus)
}

// showSplash shows an splash content during initialization.
func showSplash() {
	splashContent := container.NewVBox(
		widget.NewLabelWithStyle("Hardentools is starting up. Please wait...", fyne.TextAlignCenter, fyne.TextStyle{Monospace: true}),
		widget.NewProgressBarInfinite())

	mainWindow.SetContent(splashContent)
}

// createMainGUIContent shows the main GUI screen that allows to harden or
// restore the settings.
func createMainGUIContent(elevationStatus bool) {
	// Init variables.
	var labelText, buttonText, expertSettingsText string
	var enableHardenAdditionalButton bool
	var buttonFunc func()
	var expertSettingsCheckBox *widget.Check

	// Check if we are running with elevated rights.
	if elevationStatus == false {
		allHardenSubjects = hardenSubjectsForUnprivilegedUsers
	} else {
		allHardenSubjects = hardenSubjectsForPrivilegedUsers
	}

	// Check hardening status.
	var status = checkStatus()

	// Build up expert settings checkboxes and map.
	expertConfig = make(map[string]bool)
	expertCompWidgetArray := make([]*widget.Check, len(allHardenSubjects))

	for i, hardenSubject := range allHardenSubjects {
		var subjectIsHardened = hardenSubject.IsHardened()
		var enableField bool

		if status == false {
			// All checkboxes checked by default, disabled only if subject is already hardened.
			expertConfig[hardenSubject.Name()] = !subjectIsHardened && hardenSubject.HardenByDefault()

			// Only enable, if not already hardened.
			enableField = !subjectIsHardened
		} else {
			// Restore: only checkboxes checked which are hardened.
			expertConfig[hardenSubject.Name()] = subjectIsHardened

			// Disable all, since the user must restore all settings because otherwise
			// consecutive execution of hardentools might fail (e.g. starting powershell
			// or cmd commands) or might be ineffectiv (settings are already hardened) or
			// hardened settings might get saved as "before" settings, so user
			// can't revert to the state "before".
			enableField = false
		}

		expertCompWidgetArray[i] = widget.NewCheck(hardenSubject.LongName(), checkBoxEventGenerator(hardenSubject.Name()))
		expertCompWidgetArray[i].SetChecked(expertConfig[hardenSubject.Name()])
		if !enableField {
			expertCompWidgetArray[i].Disable()
		}
	}

	// Set labels / text fields (harden or restore).
	if status == false {
		buttonText = "Harden!"
		buttonFunc = hardenAll
		labelText = "Ready to harden some features of your system?"
		expertSettingsText = "Change only if you know what you are doing!\nDisabled settings are already hardened."
		enableHardenAdditionalButton = false
	} else {
		buttonText = "Restore..."
		buttonFunc = restoreAll
		labelText = "We have already hardened some risky features.\nDo you want to restore them?"
		expertSettingsText = "The following hardened features are going to be restored:"
		enableHardenAdditionalButton = true
	}

	// Expert tab.
	countExpertSettings := len(expertCompWidgetArray)
	expertTab1 := container.NewVBox()
	expertTab2 := container.NewVBox()
	for i, compWidget := range expertCompWidgetArray {
		if i < countExpertSettings/2 {
			expertTab1.Add(compWidget)
		} else {
			expertTab2.Add(compWidget)
		}
	}
	expertSettingsHBox := container.NewHBox(expertTab1, expertTab2)
	expertTabWidget := widget.NewCard("", "Expert Settings",
		container.NewVBox(widget.NewLabelWithStyle(expertSettingsText, fyne.TextAlignCenter, fyne.TextStyle{Italic: true}),
			expertSettingsHBox))

	// Build main GUI window's main tab.
	hardenAgainButton := widget.NewButton("Harden again (all default settings)",
		hardenDefaultsAgain)
	hardenAgainButton.Hidden = !enableHardenAdditionalButton

	hardenButton := widget.NewButton(buttonText, func() { buttonFunc() })
	hardenButton.SetIcon(theme.ConfirmIcon())

	introText := widget.NewLabelWithStyle("Hardentools is designed to disable a number of \"features\" exposed by Microsoft\n"+
		"Windows and is primary a consumer application. These features, commonly thought\n"+
		"for enterprise customers, are generally useless to regular users and rather\n"+
		"pose as dangers as they are very commonly abused by attackers to execute\n"+
		"malicious code on a victim's computer. The intent of this tool is to simply\n"+
		"reduce the attack surface by disabling the low-hanging fruit. Hardentools is\n"+
		"intended for individuals at risk, who might want an extra level of security\n"+
		"at the price of some usability. It is not intended for corporate environments.\n",
		fyne.TextAlignCenter, fyne.TextStyle{Italic: true})

	mainTabContent := container.NewVBox(
		widget.NewLabelWithStyle(labelText, fyne.TextAlignCenter, fyne.TextStyle{Bold: true}),
		hardenButton,
		hardenAgainButton,
	)
	mainTabWidget := widget.NewCard("", "", mainTabContent)

	expertSettingsCheckBox = widget.NewCheck("Show Expert Settings", func(on bool) {
		if on {
			mainWindow.SetContent(container.NewVBox(expertTabWidget, mainTabWidget))
		} else {
			mainWindow.SetContent(container.NewVBox(widget.NewCard("", "Introduction", introText), mainTabWidget))
		}
		mainWindow.CenterOnScreen()
	})
	mainTabContent.Add(expertSettingsCheckBox)
	mainWindow.SetContent(container.NewVBox(widget.NewCard("", "Introduction", introText), mainTabWidget))
	mainWindow.CenterOnScreen()
}

// showErrorDialog shows an error message.
func showErrorDialog(errorMessage string) {
	if mainWindow != nil {
		ch := make(chan bool)
		err := errors.New(errorMessage)
		errorDialog := dialog.NewError(err, mainWindow)
		errorDialog.SetOnClosed(func() {
			ch <- true
		})
		errorDialog.Show()
		<-ch
	} else {
		// no main windows - seem to be in command line mode.
		Info.Println("Error: " + errorMessage)
	}

}

// showInfoDialog shows an info message.
func showInfoDialog(infoMessage string) {
	if mainWindow != nil {
		ch := make(chan bool)
		infoDialog := dialog.NewInformation("Information", infoMessage, mainWindow)
		infoDialog.SetOnClosed(func() {
			ch <- true
		})
		infoDialog.Show()
		<-ch
	} else {
		// no main windows - seem to be in command line mode.
		Info.Println("Information: " + infoMessage)
	}
}

// showEndDialog shows the close button after hardening/restoring.
func showEndDialog(infoMessage string) {
	ch := make(chan bool)

	eventsTextAreaProgressBar.Hide()
	inProgressLabel.Hide()

	message := widget.NewLabelWithStyle(infoMessage, fyne.TextAlignCenter, fyne.TextStyle{Monospace: true})
	messageBox.Add(container.NewVBox(message,
		widget.NewButton("Close", func() {
			ch <- true
		})))

	<-ch
}

// askElevationDialog asks the user if she wants to elevates her rights.
func askElevationDialog() {
	ch := make(chan int)
	dialogText := "You are currently running hardentools as normal user.\n" +
		"You won't be able to harden all available settings!\n" +
		"If you have admin rights available, please press \"Yes\", otherwise press \"No\".\n"
	cnf := dialog.NewConfirm("Do you want to use admin privileges?", dialogText, func(response bool) {
		if response == true {
			restartWithElevatedPrivileges()
		}
		ch <- 42
	}, mainWindow)
	cnf.SetDismissText("No")
	cnf.SetConfirmText("Yes")
	cnf.Show()

	<-ch
}

// checkBoxEventGenerator is a helper function that allows GUI checkbox elements
// to call this function as a callback method. checkBoxEventGenerator then saves
// the requested expert config setting for the checkbox in the corresponding map.
func checkBoxEventGenerator(hardenSubjName string) func(on bool) {
	var hardenSubjectName = hardenSubjName
	return func(on bool) {
		expertConfig[hardenSubjectName] = on
	}
}

// restartWithElevatedPrivileges tries to restart hardentools.exe with admin
// privileges.
func restartWithElevatedPrivileges() {
	// Find out our program (exe) name.
	progName := os.Args[0]

	// Start us again, this time with elevated privileges.
	if C.ExecuteWithRunas(C.CString(progName)) == 1 {
		// Exit this instance (the unprivileged one).
		os.Exit(0)
	} else {
		// Something went wrong.
		showErrorDialog("Error while trying to gain elevated privileges. Starting in unprivileged mode...")
	}
}

// showEventsTextArea updates the UI to show the harden/restore progress and
// the final status of the hardened settings.
func showEventsTextArea() {
	// init map that remembers stateIcons.
	stateLabels = make(map[string]*widget.Label, len(hardenSubjectsForPrivilegedUsers))

	firstColumn = container.NewVBox(widget.NewLabelWithStyle("Harden Item Name",
		fyne.TextAlignLeading, fyne.TextStyle{Bold: true}))
	secondColumn = container.NewVBox(widget.NewLabelWithStyle("Operation Result",
		fyne.TextAlignLeading, fyne.TextStyle{Bold: true}))
	thirdColumn = container.NewVBox(widget.NewLabelWithStyle("Verification Result",
		fyne.TextAlignLeading, fyne.TextStyle{Bold: true}))

	resultBox := container.NewHBox(
		firstColumn,
		secondColumn,
		thirdColumn)

	resultBoxContainer := container.NewVScroll(resultBox)
	resultBoxContainer.SetMinSize(fyne.NewSize(500, 600))
	resultBoxGroup := widget.NewCard("", "", resultBoxContainer)

	messageBox = container.NewVBox()
	inProgressLabel = widget.NewLabelWithStyle("Operation in progress...",
		fyne.TextAlignCenter, fyne.TextStyle{})
	messageBox.Add(inProgressLabel)
	eventsTextAreaProgressBar = widget.NewProgressBarInfinite()
	messageBox.Add(eventsTextAreaProgressBar)

	eventsArea := container.NewVBox(messageBox, resultBoxGroup)
	mainWindow.SetContent(eventsArea)
	mainWindow.CenterOnScreen()
}

// ShowSuccess sets GUI status of name field to success
func ShowSuccess(name string) {
	if mainWindow != nil {
		stateLabels[name] = widget.NewLabel("...")

		firstColumn.Add(container.NewHBox(widget.NewLabel(name)))
		secondColumn.Add(container.NewHBox(widget.NewLabel("Success")))
		thirdColumn.Add(container.NewHBox(stateLabels[name]))
	} else {
		Info.Println(name + ": Success")
	}
}

// ShowFailure sets GUI status of name field to failureText
func ShowFailure(name, failureText string) {
	if mainWindow != nil {
		stateLabels[name] = widget.NewLabel("...")
		firstColumn.Add(container.NewHBox(widget.NewLabel(name)))
		secondColumn.Add(container.NewHBox(widget.NewLabelWithStyle("FAIL", fyne.TextAlignLeading, fyne.TextStyle{Bold: true})))
		thirdColumn.Add(container.NewHBox(stateLabels[name]))

		showErrorDialog(name + " failed with error:\n" + failureText)
	} else {
		Info.Println(name + " failed with error: " + failureText)
	}
}

// ShowIsHardened sets GUI result for name to is hardened
func ShowIsHardened(name string) {
	label := stateLabels[name]
	if label != nil {
		label.SetText("is hardened")
	} else {
		stateLabels[name] = widget.NewLabel("is hardened")

		firstColumn.Add(container.NewHBox(widget.NewLabel(name)))
		secondColumn.Add(container.NewHBox(widget.NewLabel("not selected")))
		thirdColumn.Add(container.NewHBox(stateLabels[name]))
	}
}

// ShowNotHardened sets GUI result for name to not hardened
func ShowNotHardened(name string) {
	label := stateLabels[name]
	if label != nil {
		label.SetText("not hardened")
	} else {
		stateLabels[name] = widget.NewLabel("not hardened")

		firstColumn.Add(container.NewHBox(widget.NewLabel(name)))
		secondColumn.Add(container.NewHBox(widget.NewLabel("not selected")))
		thirdColumn.Add(container.NewHBox(stateLabels[name]))
	}
}

func cmdHarden() {
	cmdHardenRestore(true)

	Info.Println("Done! Risky features have been hardened!\nFor all changes to take effect please restart Windows.")
	os.Exit(0)
}

func cmdRestore() {
	cmdHardenRestore(false)

	Info.Println("Done! Restored settings to their original state.\nFor all changes to take effect please restart Windows.")
	os.Exit(0)
}

func cmdHardenRestore(harden bool) {
	// check if hardentools has been started with elevated rights.
	elevationStatus := false
	if C.IsElevated() == 1 {
		elevationStatus = true
		Info.Println("Started with elevated rights")
	} else {
		Info.Println("Started without elevated rights")
	}

	// check if we are running with elevated rights
	if elevationStatus == false {
		allHardenSubjects = hardenSubjectsForUnprivilegedUsers
	} else {
		allHardenSubjects = hardenSubjectsForPrivilegedUsers
	}

	// check hardening status
	status := checkStatus()
	if status == false && harden == false {
		fmt.Println("Not hardened. Please harden before restoring.")
		os.Exit(-1)
	} else if status == true && harden == true {
		fmt.Println("Already hardened. Please restore before hardening again.")
		os.Exit(-1)
	}

	// build up expert settings checkboxes and map
	expertConfig = make(map[string]bool)
	for _, hardenSubject := range allHardenSubjects {
		var subjectIsHardened = hardenSubject.IsHardened()
		//var enableField bool

		if status == false {
			// harden only settings which are not hardened yet
			expertConfig[hardenSubject.Name()] = !subjectIsHardened && hardenSubject.HardenByDefault()
		} else {
			// restore only hardened settings
			expertConfig[hardenSubject.Name()] = subjectIsHardened
		}
	}

	triggerAll(harden)
	if !harden {
		restoreSavedRegistryKeys()
	}
	markStatus(harden)
	showStatus(true)
}
