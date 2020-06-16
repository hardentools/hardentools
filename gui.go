// Hardentools
// Copyright (C) 2020 Security Without Borders
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
// along with this program.  If not, see <http://wweventsDialog.gnu.org/licenses/>.

package main

/*
// some C code for managing elevated privileges
#include <windows.h>
#include <shellapi.h>

// checks if we are running with elevated privileges (admin rights)
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

// executes the executable in the current directory (or in path) with "runas"
// to aquire admin privileges
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
	"flag"
	"io/ioutil"
	"os"
	"strings"

	"fyne.io/fyne"
	"fyne.io/fyne/dialog"
	"fyne.io/fyne/theme"
	"fyne.io/fyne/widget"
)

var messageBox, firstColumn, secondColumn, thirdColumn *widget.Box
var eventsTextAreaProgressBar *widget.ProgressBarInfinite
var stateLabels map[string]*widget.Label
var inProgressLabel *widget.Label

func main2() {
	// check if hardentools has been started with elevated rights. If not
	// ask user if he wants to elevate
	if C.IsElevated() == 0 {
		// main window must already be open for this dialog to work
		askElevationDialog()
	}
	elevationStatus := false
	if C.IsElevated() == 1 {
		elevationStatus = true
	}

	// show splash screen since loading takes some time (at least with admin
	// privileges) due to sequential reading of all the settings
	showSplash()

	// parse command line parameters/flags
	flag.String("log-level", defaultLogLevel, "Info|Trace: enables logging with verbosity; Off: disables logging")
	flag.Parse()
	flag.VisitAll(func(f *flag.Flag) {
		// only supports log-level right now
		if f.Name == "log-level" {
			// Init logging
			if strings.EqualFold(f.Value.String(), "Info") {
				var logfile, err = os.Create(logpath)
				if err != nil {
					panic(err)
				}

				initLogging(ioutil.Discard, logfile)
			} else if strings.EqualFold(f.Value.String(), "Trace") {
				var logfile, err = os.Create(logpath)
				if err != nil {
					panic(err)
				}

				initLogging(logfile, logfile)
			} else {
				// Off
				initLogging(ioutil.Discard, ioutil.Discard)
			}
		}
	})

	// show main screen
	createMainGUIContent(elevationStatus)
}

// showSplash shows an splash content during initialization
func showSplash() {
	splashContent := widget.NewVBox(
		widget.NewLabelWithStyle("Hardentools is starting up. Please wait...", fyne.TextAlignCenter, fyne.TextStyle{Monospace: true}),
		widget.NewProgressBarInfinite())

	mainWindow.SetContent(splashContent)
}

// createMainGUIContent shows the main GUI screen that allows to harden or
// restore the settings
func createMainGUIContent(elevationStatus bool) {
	// init variables
	var labelText, buttonText, expertSettingsText string
	var enableHardenAdditionalButton bool
	var buttonFunc func()
	var expertSettingsCheckBox *widget.Check

	// check if we are running with elevated rights
	if elevationStatus == false {
		allHardenSubjects = allHardenSubjectsForUnprivilegedUsers
	} else {
		allHardenSubjects = allHardenSubjectsWithAndWithoutElevatedPrivileges
	}

	// check hardening status
	var status = checkStatus()

	// build up expert settings checkboxes and map
	expertConfig = make(map[string]bool)
	expertCompWidgetArray := make([]*widget.Check, len(allHardenSubjects))

	for i, hardenSubject := range allHardenSubjects {
		var subjectIsHardened = hardenSubject.IsHardened()
		var enableField bool

		if status == false {
			// all checkboxes checked by default, disabled only if subject is already hardened
			expertConfig[hardenSubject.Name()] = !subjectIsHardened && hardenSubject.HardenByDefault()

			// only enable, if not already hardenend
			enableField = !subjectIsHardened
		} else {
			// restore: only checkboxes checked which are hardenend
			expertConfig[hardenSubject.Name()] = subjectIsHardened

			// disable all, since the user must restore all settings because otherwise
			// consecutive execution of hardentools might fail (e.g. starting powershell
			// or cmd commands) or might be ineffectiv (settings are already hardened) or
			// hardened settings might get saved as "before" settings, so user
			// can't revert to the state "before"
			enableField = false
		}

		expertCompWidgetArray[i] = widget.NewCheck(hardenSubject.LongName(), checkBoxEventGenerator(hardenSubject.Name()))
		expertCompWidgetArray[i].SetChecked(expertConfig[hardenSubject.Name()])
		if !enableField {
			expertCompWidgetArray[i].Disable()
		}
	}

	// set labels / text fields (harden or restore)
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

	// expert tab
	countExpertSettings := len(expertCompWidgetArray)
	expertTab1 := widget.NewVBox()
	expertTab2 := widget.NewVBox()
	for i, compWidget := range expertCompWidgetArray {
		if i < countExpertSettings/2 {
			expertTab1.Append(compWidget)
		} else {
			expertTab2.Append(compWidget)
		}
	}
	expertSettingsHBox := widget.NewHBox(expertTab1, expertTab2)
	expertTabWidget := widget.NewGroup("Expert Settings",
		widget.NewLabelWithStyle(expertSettingsText, fyne.TextAlignCenter, fyne.TextStyle{Italic: true}),
		expertSettingsHBox,
	)

	// build up main GUI window
	// main tab
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

	mainTabContent := widget.NewVBox(
		widget.NewLabelWithStyle(labelText, fyne.TextAlignCenter, fyne.TextStyle{Bold: true}),
		hardenButton,
		hardenAgainButton,
	)
	mainTabWidget := widget.NewGroup("Harden", mainTabContent)

	expertSettingsCheckBox = widget.NewCheck("Show Expert Settings", func(on bool) {
		if on {
			mainWindow.SetContent(widget.NewVBox(expertTabWidget, mainTabWidget))
		} else {
			mainWindow.SetContent(widget.NewVBox(widget.NewGroup("Introduction", introText), mainTabWidget))
		}
	})
	mainTabContent.Append(expertSettingsCheckBox)

	mainWindow.SetContent(widget.NewVBox(widget.NewGroup("Introduction", introText), mainTabWidget))
	mainWindow.CenterOnScreen()
}

// showErrorDialog shows an error message
func showErrorDialog(errorMessage string) {
	ch := make(chan bool)
	err := errors.New(errorMessage)
	errorDialog := dialog.NewError(err, mainWindow)
	errorDialog.SetOnClosed(func() {
		ch <- true
	})
	errorDialog.Show()
	<-ch
}

// showInfoDialog shows an info message
func showInfoDialog(infoMessage string) {
	ch := make(chan bool)
	infoDialog := dialog.NewInformation("Information", infoMessage, mainWindow)
	infoDialog.SetOnClosed(func() {
		ch <- true
	})
	infoDialog.Show()
	<-ch

}

// showEndDialog shows the close button after hardening/restoring
func showEndDialog(infoMessage string) {
	ch := make(chan bool)

	eventsTextAreaProgressBar.Hide()
	inProgressLabel.Hide()

	message := widget.NewLabelWithStyle(infoMessage, fyne.TextAlignCenter, fyne.TextStyle{Monospace: true})
	messageBox.Prepend(widget.NewVBox(message,
		widget.NewButton("Close", func() {
			ch <- true
		})))

	<-ch
}

// askElevationDialog asks the user if he wants to elevates his rights
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
// the requested expert config setting for the checkbox in the corresponding map
func checkBoxEventGenerator(hardenSubjName string) func(on bool) {
	var hardenSubjectName = hardenSubjName
	return func(on bool) {
		expertConfig[hardenSubjectName] = on
	}
}

// restartWithElevatedPrivileges tries to restart hardentools.exe with admin
// privileges
func restartWithElevatedPrivileges() {
	// find out our program (exe) name
	progName := os.Args[0]

	// start us again, this time with elevated privileges
	if C.ExecuteWithRunas(C.CString(progName)) == 1 {
		// exit this instance (the unprivileged one)
		os.Exit(0)
	} else {
		// something went wrong
		showErrorDialog("Error while trying to gain elevated privileges. Starting in unprivileged mode...")
	}
}

// showEventsTextArea updates the UI to show the harden/restore progress and
// the final status of the hardenend settings
func showEventsTextArea() {
	// init map that remembers stateIcons
	stateLabels = make(map[string]*widget.Label, len(allHardenSubjectsWithAndWithoutElevatedPrivileges))

	firstColumn = widget.NewVBox(widget.NewLabelWithStyle("Harden Item Name", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}))
	secondColumn = widget.NewVBox(widget.NewLabelWithStyle("Operation Result", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}))
	thirdColumn = widget.NewVBox(widget.NewLabelWithStyle("Verification Result", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}))

	resultBox := widget.NewHBox(
		firstColumn,
		secondColumn,
		thirdColumn)

	resultBoxScrollContainer := widget.NewScrollContainer(resultBox)
	resultBoxScrollContainer.SetMinSize(fyne.NewSize(500, 400))
	resultBoxGroup := widget.NewGroup("Result Details", resultBoxScrollContainer)
	resultBoxGroup.Hide()

	messageBox = widget.NewVBox()
	inProgressLabel = widget.NewLabelWithStyle("Hardening in progress...", fyne.TextAlignCenter, fyne.TextStyle{})
	messageBox.Append(inProgressLabel)
	eventsTextAreaProgressBar = widget.NewProgressBarInfinite()
	messageBox.Append(eventsTextAreaProgressBar)
	var resultDetailsButton *widget.Button
	resultDetailsButton = widget.NewButton("Show Result Details", func() {
		resultBoxGroup.Show()
		resultDetailsButton.Hide()
	})
	messageBox.Append((resultDetailsButton))

	eventsArea := widget.NewVBox(messageBox, resultBoxGroup)
	mainWindow.SetContent(eventsArea)
}

func ShowSuccess(name string) {
	stateLabels[name] = widget.NewLabel("...")

	firstColumn.Append(widget.NewHBox(widget.NewLabel(name)))
	secondColumn.Append(widget.NewHBox(widget.NewLabel("Success")))
	thirdColumn.Append(widget.NewHBox(stateLabels[name]))
}

func ShowFailure(name, failureText string) {
	stateLabels[name] = widget.NewLabel("...")

	firstColumn.Append(widget.NewHBox(widget.NewLabel(name)))
	secondColumn.Append(widget.NewHBox(widget.NewLabelWithStyle("FAIL", fyne.TextAlignLeading, fyne.TextStyle{Bold: true})))
	thirdColumn.Append(widget.NewHBox(stateLabels[name]))

	//additionally show error dialog
	showErrorDialog(name + " failed with error:\n" + failureText)
}

func ShowIsHardened(name string) {
	label := stateLabels[name]
	if label != nil {
		label.SetText("is hardened")
	} else {
		stateLabels[name] = widget.NewLabel("is hardened")

		firstColumn.Append(widget.NewHBox(widget.NewLabel(name)))
		secondColumn.Append(widget.NewHBox(widget.NewLabel("not selected")))
		thirdColumn.Append(widget.NewHBox(stateLabels[name]))
	}
}

func ShowNotHardened(name string) {
	label := stateLabels[name]
	if label != nil {
		label.SetText("not hardened")
	} else {
		stateLabels[name] = widget.NewLabel("not hardened")

		firstColumn.Append(widget.NewHBox(widget.NewLabel(name)))
		secondColumn.Append(widget.NewHBox(widget.NewLabel("not selected")))
		thirdColumn.Append(widget.NewHBox(stateLabels[name]))
	}
}
