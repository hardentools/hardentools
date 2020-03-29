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
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"github.com/lxn/walk"
	"github.com/lxn/walk/declarative"
)

var expertCompWidgetArray []declarative.Widget
var events *walk.TextEdit
var window *walk.MainWindow

// openMainWindows opens the main window
func openMainWindow(splashChannel chan bool, elevationStatus bool) {
	// init variables
	var labelText, buttonText, eventsText, expertSettingsText string
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

	// parse command line parameters/flags
	flag.String("log-level", defaultLogLevel, "Info|Trace: enables logging with verbosity; Off: disables logging")
	flag.Parse()
	flag.VisitAll(func(f *flag.Flag) {
		//fmt.Printf("%s = \"%s\"\n", f.Name, f.Value.String())
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

	// build up expert settings checkboxes and map
	expertConfig = make(map[string]bool)
	expertCompWidgetArray = make([]declarative.Widget, len(allHardenSubjects))
	var checkBoxArray = make([]*walk.CheckBox, len(allHardenSubjects))

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

		expertCompWidgetArray[i] = declarative.CheckBox{
			AssignTo:         &checkBoxArray[i],
			Name:             hardenSubject.Name(),
			Text:             hardenSubject.LongName(),
			Checked:          expertConfig[hardenSubject.Name()],
			OnCheckedChanged: walk.EventHandler(checkBoxEventGenerator(i, hardenSubject.Name())),
			Enabled:          enableField,
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
	//	window
	declarative.MainWindow{
		AssignTo: &window,
		Title:    "HardenTools - Security Without Borders",
		//MinSize:  declarative.Size{500, 600},
		Layout: declarative.VBox{},
		DataBinder: declarative.DataBinder{
			DataSource: expertConfig,
			AutoSubmit: true,
		},
		Children: []declarative.Widget{
			declarative.HSpacer{},
			declarative.PushButton{
				Text:      "Harden again (all default settings)",
				OnClicked: hardenDefaultsAgain,
				Visible:   enableHardenAdditionalButton,
			},
			declarative.HSpacer{},
			declarative.Label{Text: labelText},
			declarative.PushButton{
				Text:      buttonText,
				OnClicked: buttonFunc,
			},
			declarative.HSpacer{},
			declarative.Label{Text: expertSettingsText},
			declarative.Composite{
				Layout:   declarative.Grid{Columns: 3},
				Border:   true,
				Children: expertCompWidgetArray,
			},
			declarative.TextEdit{
				AssignTo: &events,
				Text:     eventsText,
				ReadOnly: true,
				MinSize:  declarative.Size{500, 450},
				Visible:  false,
			},
		},
	}.Create()

	// hide splash screen
	splashChannel <- true

	// start main GUI
	window.Run()
}

// checkBoxEventGenerator generates a function that is used as an walk.EventHandler
// for the expert CheckBoxes in main GUI
func checkBoxEventGenerator(n int, hardenSubjName string) func() {
	var i = n
	var hardenSubjectName = hardenSubjName
	return func() {
		x := *(expertCompWidgetArray[i]).(declarative.CheckBox).AssignTo
		isChecked := x.CheckState()
		expertConfig[hardenSubjectName] = (isChecked == walk.CheckChecked)
	}
}

// showSplash shows an splash screen during initialization
func showSplash(splashChannel chan bool) {
	var splashWindow *walk.MainWindow
	declarative.MainWindow{
		AssignTo: &splashWindow,
		Title:    "HardenTools - HardenTools - Starting Up. Please wait.",
		MinSize:  declarative.Size{600, 100},
	}.Create()

	// wait for main gui, then hide splash
	go func() {
		<-splashChannel
		splashWindow.Hide()
	}()
}

// showEventsTextArea sets the events area to visible and disables action buttons
func showEventsTextArea() {
	// set the events text element to visible to display output
	events.SetVisible(true)

	// set all other items but the last (which is the events text element from
	// above) to disabled so no further action is possible by the user
	length := window.Children().Len()
	for i := 0; i < length-1; i++ {
		window.Children().At(i).SetEnabled(false)
	}
}

// showErrorDialog shows an error message
func showErrorDialog(errorMessage string) {
	walk.MsgBox(nil, "ERROR", errorMessage, walk.MsgBoxIconExclamation)
}

// showInfoDialog shows an error message
func showInfoDialog(infoMessage string) {
	walk.MsgBox(nil, "Information", infoMessage, walk.MsgBoxIconInformation)
}

// askElevationDialog asks the user if he wants to elevates his rights
func askElevationDialog() {
	//var notifyTextEdit *walk.TextEdit
	var dialog *walk.Dialog
	var acceptPB, cancelPB *walk.PushButton
	_, err := declarative.Dialog{
		AssignTo:      &dialog,
		Title:         "Do you want to use admin privileges?",
		DefaultButton: &acceptPB,
		CancelButton:  &cancelPB,
		MinSize:       declarative.Size{300, 100},
		Layout:        declarative.VBox{},
		Children: []declarative.Widget{

			declarative.Label{
				Text: "You are currently running hardentools as normal user.",
				//TextColor: walk.RGB(255, 0, 0),
				//MinSize: declarative.Size{500, 50},
			},
			declarative.Label{
				Text:      "You won't be able to harden all available settings!",
				TextColor: walk.RGB(255, 0, 0),
				//MinSize:   declarative.Size{500, 50},
			},
			declarative.Label{
				Text: "If you have admin rights available, please press \"Yes\", otherwise press \"No\".",
				//TextColor: walk.RGB(255, 0, 0),
				//MinSize: declarative.Size{500, 50},
			},
			declarative.Composite{
				Layout: declarative.HBox{},
				Children: []declarative.Widget{
					declarative.PushButton{
						AssignTo: &acceptPB,
						Text:     "Yes",

						OnClicked: func() {
							dialog.Accept()
							restartWithElevatedPrivileges()
						},
					},
					declarative.PushButton{
						AssignTo:  &cancelPB,
						Text:      "No",
						OnClicked: func() { dialog.Cancel() },
					},
				},
			},
		},
	}.Run(nil)
	if err != nil {
		fmt.Println(err)
	}
}
