// Hardentools
// Copyright (C) 2017-2022 Security Without Borders
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

//go:build !cli

package main

import (
	"errors"
	"os"
	"strings"

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
	mainWindow.CenterOnScreen()

	// Check if hardentools has been started with elevated rights. If not
	// ask user if she wants to elevate.
	elevationStatus := isElevated()
	if elevationStatus == false {
		// Main window must already be open for this dialog to work.
		askElevationDialog()
	}

	// Show main screen.
	createMainGUIContent(elevationStatus)
}

// createMainGUIContent shows the main GUI screen that allows to harden or
// restore the settings.
func createMainGUIContent(elevationStatus bool) {
	// Init variables.
	var labelText, buttonText, expertSettingsText string
	var enableHardenAdditionalButton bool
	var buttonFunc func()
	var expertSettingsCheckBox *widget.Check
	var mainWindowContainer *fyne.Container

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
	expertCompWidgetArray := make([]*fyne.Container, len(allHardenSubjects))

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

		// setup check box widget
		checkBoxEventFunc := func(hardenSubjName string) func(on bool) {
			return func(on bool) {
				expertConfig[hardenSubjName] = on
			}
		}(hardenSubject.Name())
		check := widget.NewCheck(hardenSubject.LongName(), checkBoxEventFunc)
		check.SetChecked(expertConfig[hardenSubject.Name()])
		if !enableField {
			check.Disable()
		}

		// setup help widget
		onTapFunc := func(description string) func() {
			return func() {
				showInfoDialog(description)
			}
		}(hardenSubject.Description())
		help := widget.NewButtonWithIcon("", theme.HelpIcon(), onTapFunc)

		expertCompWidgetArray[i] = container.NewHBox(help, check)
	}

	// Setup labels / text fields (harden or restore).
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
	expertTab3 := container.NewVBox()
	for i, compWidget := range expertCompWidgetArray {
		if i < countExpertSettings/3 {
			expertTab1.Add(compWidget)
		} else if i < countExpertSettings/3*2 {
			expertTab2.Add(compWidget)
		} else {
			expertTab3.Add(compWidget)
		}
	}
	expertSettingsHBox := container.NewHBox(expertTab1, expertTab2, expertTab3)
	expertTabWidget := widget.NewCard("", "Expert Settings",
		container.NewVBox(widget.NewLabelWithStyle(expertSettingsText, fyne.TextAlignCenter, fyne.TextStyle{}),
			expertSettingsHBox))

	// Build main GUI window's main tab.
	hardenAgainButton := widget.NewButton("Harden again (all default settings)",
		hardenDefaultsAgain)
	hardenAgainButton.Hidden = !enableHardenAdditionalButton

	hardenButton := widget.NewButton(buttonText, func() { buttonFunc() })
	hardenButton.SetIcon(theme.ConfirmIcon())

	introText := widget.NewLabelWithStyle("Hardentools is designed to disable a number of"+
		" \"features\" exposed by Microsoft\n"+
		"Windows and some widely used applications (Microsoft Office and Adobe PDF\n Reader, "+
		"for now). These features, commonly thought for enterprise customers,\n"+
		"are generally useless to regular users and rather pose as dangers as\n"+
		"they are very commonly abused by attackers to execute malicious code\n"+
		"on a victim's computer. The intent of this tool is to simply reduce\n"+
		"the attack surface by disabling the low-hanging fruit. Hardentools is\n"+
		"for individuals at risk, who might want an extra level of security intended\n"+
		"at the price of some usability. It is not intended for corporate environments.\n",
		fyne.TextAlignCenter, fyne.TextStyle{})

	mainTabContent := container.NewVBox(
		widget.NewLabelWithStyle(labelText, fyne.TextAlignCenter, fyne.TextStyle{Bold: true}),
		hardenButton,
		hardenAgainButton,
	)
	mainTabWidget := widget.NewCard("", "", mainTabContent)

	// setup help widget
	onTapFuncForMainTab := func(hardenSubjects []HardenInterface) func() {
		helpText := "The following hardenings are available in Hardentools.\nYou" +
			" can deactivate hardenings or activate additional\nhardenings using the expert settings.\n" +
			"Note: Most hardenings are only available with admin privileges.:\n\n"
		for _, hardenSubject := range hardenSubjects {
			if hardenSubject.HardenByDefault() {
				helpText += "• " + hardenSubject.LongName() + ":\n\t" +
					strings.Replace(hardenSubject.Description(), "\n", "\n\t", -1) + "\n\n"
			} else {
				helpText += "• " + hardenSubject.LongName() + " (not active by default):\n\t" +
					strings.Replace(hardenSubject.Description(), "\n", "\n\t", -1) + "\n\n"
			}
		}
		return func() {
			w := appl.NewWindow("Hardentools - Help")
			scroller := container.NewVScroll(widget.NewLabel(helpText))
			scroller.SetMinSize(fyne.NewSize(500, 600))
			w.SetContent(scroller)
			w.Show()
		}
	}(hardenSubjectsForPrivilegedUsers)
	help := widget.NewButtonWithIcon("", theme.HelpIcon(), onTapFuncForMainTab)

	expertSettingsCheckBox = widget.NewCheck("Show Expert Settings", func(on bool) {
		if on {
			mainWindowContainer.RemoveAll()
			mainWindowContainer.AddObject(container.NewVBox(expertTabWidget, mainTabWidget))
		} else {
			introTextWidget := widget.NewCard("", "Introduction", introText)
			introAndHelpContainer := container.NewBorder(nil, nil, nil, help, introTextWidget)
			mainWindowContainer.RemoveAll()
			mainWindowContainer.AddObject(container.NewVBox(introAndHelpContainer, mainTabWidget))
		}
		mainWindow.CenterOnScreen()
	})
	mainTabContent.Add(expertSettingsCheckBox)

	introTextWidget := widget.NewCard("", "Introduction", introText)
	introAndHelpContainer := container.NewBorder(nil, nil, nil, help, introTextWidget)
	mainWindowContainer = container.NewVBox(introAndHelpContainer, mainTabWidget)
	fyne.Do(func() {
		mainWindow.SetContent(mainWindowContainer)
		mainWindow.CenterOnScreen()
	})

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
		infoDialog := dialog.NewInformation("Information", infoMessage, mainWindow)
		infoDialog.Show()
	} else {
		// no main windows - seem to be in command line mode.
		Info.Println("Information: " + infoMessage)
	}
}

// showEndDialog shows the close button after hardening/restoring.
func showEndDialog(infoMessage string) {
	ch := make(chan bool)

	fyne.Do(func() {
		eventsTextAreaProgressBar.Hide()
		inProgressLabel.Hide()
	})
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

// restartWithElevatedPrivileges tries to restart hardentools.exe with admin
// privileges.
func restartWithElevatedPrivileges() {
	// Find out our program (exe) name.
	progName := os.Args[0]

	// Start us again, this time with elevated privileges.
	if startWithElevatedPrivs(progName) {
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
	fyne.Do(func() {
		mainWindow.SetContent(eventsArea)
		mainWindow.CenterOnScreen()
	})
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
		fyne.Do(func() {
			label.SetText("is hardened")
		})
	} else {
		stateLabels[name] = widget.NewLabel("is hardened")

		fyne.Do(func() {
			firstColumn.Add(container.NewHBox(widget.NewLabel(name)))
			secondColumn.Add(container.NewHBox(widget.NewLabel("not selected")))
			thirdColumn.Add(container.NewHBox(stateLabels[name]))
		})
	}
}

// ShowNotHardened sets GUI result for name to not hardened
func ShowNotHardened(name string) {
	label := stateLabels[name]
	if label != nil {
		fyne.Do(func() {
			label.SetText("not hardened")
		})
	} else {
		stateLabels[name] = widget.NewLabel("not hardened")

		fyne.Do(func() {
			firstColumn.Add(container.NewHBox(widget.NewLabel(name)))
			secondColumn.Add(container.NewHBox(widget.NewLabel("not selected")))
			thirdColumn.Add(container.NewHBox(stateLabels[name]))
		})
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

// hardenAll starts harden procedure.
func hardenAll() {
	showEventsTextArea()

	// Use goroutine to allow gui to update window.
	go func() {
		triggerAll(true)
		markStatus(true)
		showStatus()

		showEndDialog("Done! Risky features have been hardened!\nFor all changes to take effect please restart Windows.")
		os.Exit(0)
	}()
}

// RestoreAll starts restore procedure.
func restoreAll() {
	showEventsTextArea()

	// Use goroutine to allow gui to update window.
	go func() {
		triggerAll(false)
		restoreSavedRegistryKeys() // TODO: add error handling/visibility to user
		markStatus(false)
		showStatus()

		showEndDialog("Done! Restored settings to their original state.\nFor all changes to take effect please restart Windows.")
		os.Exit(0)
	}()
}

// hardenDefaultsAgain restores the original settings and
// hardens using the default settings (no custom settings apply).
func hardenDefaultsAgain() {
	showEventsTextArea()

	// Use goroutine to allow gui to update window.
	go func() {
		// Restore hardened settings.
		triggerAll(false)
		restoreSavedRegistryKeys()
		markStatus(false)

		// Reset expertConfig (is set to currently already hardened settings
		// in case of restore).
		expertConfig = make(map[string]bool)
		for _, hardenSubject := range allHardenSubjects {
			expertConfig[hardenSubject.Name()] = hardenSubject.HardenByDefault()
		}

		// Harden all settings.
		triggerAll(true)
		markStatus(true)
		showStatus()

		showEndDialog("Done!\nRisky features have been hardened!\nFor all changes to take effect please restart Windows.")
		os.Exit(0)
	}()
}
