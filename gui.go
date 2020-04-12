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
	"fyne.io/fyne/layout"
	"fyne.io/fyne/theme"
	"fyne.io/fyne/widget"
)

var events = widget.NewMultiLineEntry()

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

	createMainGUIContent(elevationStatus)
}

// restartWithElevatedPrivileges tries to restart hardentools.exe with admin privileges
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

func createMainGUIContent(elevationStatus bool) {
	// init variables
	var labelText, buttonText, expertSettingsText string
	var enableHardenAdditionalButton bool
	var buttonFunc func()

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
		expertSettingsText = "Expert Settings - change only if you now what you are doing! Disabled settings are already hardened."
		enableHardenAdditionalButton = false
	} else {
		buttonText = "Restore..."
		buttonFunc = restoreAll
		labelText = "We have already hardened some risky features, do you want to restore them?"
		expertSettingsText = "The following hardened features are going to be restored:"
		enableHardenAdditionalButton = true
	}

	// build up main GUI window
	// main tab
	hardenAgainButton := widget.NewButton("Harden again (all default settings)",
		hardenDefaultsAgain)
	hardenAgainButton.Hidden = !enableHardenAdditionalButton

	mainTabWidget := widget.NewVBox(
		fyne.NewContainerWithLayout(layout.NewGridLayout(1),
			widget.NewLabel(labelText),
			widget.NewButton(buttonText, func() { buttonFunc() }),
			hardenAgainButton,
		),
	)

	// expert tab
	expertTabWidget := widget.NewVBox(
		widget.NewLabel(expertSettingsText),
	)
	for _, compWidget := range expertCompWidgetArray {
		expertTabWidget.Append(compWidget)
	}

	//	window
	tabs := widget.NewTabContainer(
		widget.NewTabItemWithIcon("Main", theme.HomeIcon(), mainTabWidget),
		widget.NewTabItemWithIcon("Advanced", theme.SettingsIcon(), expertTabWidget))
	tabs.SetTabLocation(widget.TabLocationLeading)
	//tabs.SelectTabIndex(appl.Preferences().Int("currentTab"))
	mainWindow.SetContent(tabs)
}

// showSplash shows an splash content during initialization
func showSplash() {
	splashContent := widget.NewVBox(
		widget.NewLabel("Hardentools is starting up. Please wait..."),
		widget.NewProgressBarInfinite())

	mainWindow.SetContent(splashContent)
}

// showEventsTextArea
func showEventsTextArea() {
	// log tab widget
	events.SetReadOnly(true)
	mainWindow.SetContent(events)
	mainWindow.SetFixedSize(true)
	mainWindow.Resize(fyne.NewSize(600, 800))
}

// showErrorDialog shows an error message
func showErrorDialog(errorMessage string) {
	ch := make(chan int)

	err := errors.New(errorMessage)
	dialog.ShowErrorWithCallback(err, func() {
		ch <- 42
	}, mainWindow)

	<-ch
}

// showInfoDialog shows an error message
func showInfoDialog(infoMessage string) {
	ch := make(chan int)

	dialog.ShowInformationWithCallback("Information", infoMessage,
		func() {
			ch <- 42
		}, mainWindow)

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

func checkBoxEventGenerator(hardenSubjName string) func(on bool) {
	var hardenSubjectName = hardenSubjName
	return func(on bool) {
		expertConfig[hardenSubjectName] = on
	}
}

func PrintEvent(text string) {
	events.SetText(events.Text + text)
}
