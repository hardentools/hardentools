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

import (
	"errors"

	"fyne.io/fyne"
	"fyne.io/fyne/app"
	"fyne.io/fyne/dialog"
	"fyne.io/fyne/layout"
	"fyne.io/fyne/theme"
	"fyne.io/fyne/widget"
)

var events = widget.NewMultiLineEntry()

func openMainWindow(splashChannel chan bool, elevationStatus bool, appl fyne.App) {
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
	tabs.SelectTabIndex(appl.Preferences().Int("currentTab"))
	mainWindow.SetContent(tabs)

	// hide splash screen
	splashChannel <- true

	mainWindow.ShowAndRun()
}

// showSplash shows an splash screen during initialization
func showSplash(splashChannel chan bool) {
	appl := app.New()
	appl.Settings().SetTheme(theme.LightTheme())
	splashWindow := appl.NewWindow("Hardentools is starting up")
	splashWindow.Resize(fyne.NewSize(600, 300))
	splashWindow.SetFixedSize(true)
	splashWindow.Show()

	// wait for main gui, then hide splash
	go func() {
		<-splashChannel
		splashWindow.Hide()
	}()
}

// showEventsTextArea sets the events area to visible and disables action buttons
func showEventsTextArea() {
	// set the events text element to visible to display output

	// log tab widget
	events.SetReadOnly(true)
	mainWindow.SetContent(events)
	mainWindow.SetFixedSize(true)
	mainWindow.Resize(fyne.NewSize(600, 800))
	//mainWindow.Close()
	//eventsWindow.Show()
}

// showErrorDialog shows an error message
func showErrorDialog(errorMessage string) {
	err := errors.New(errorMessage)
	dialog.ShowError(err, mainWindow)
}

// showInfoDialog shows an error message
func showInfoDialog(infoMessage string) {
	dialog.ShowInformation("Information", infoMessage, mainWindow)
}

func elevationDialogCallback(response bool) {
	if response == true {
		restartWithElevatedPrivileges()
	}
}

// askElevationDialog asks the user if he wants to elevates his rights
func askElevationDialog() {
	dialogText := "You are currently running hardentools as normal user.\n" +
		"You won't be able to harden all available settings!\n" +
		"If you have admin rights available, please press \"Yes\", otherwise press \"No\".\n"
	cnf := dialog.NewConfirm("Do you want to use admin privileges?", dialogText, elevationDialogCallback, mainWindow)
	cnf.SetDismissText("No")
	cnf.SetConfirmText("Yes")
	cnf.Show()
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
