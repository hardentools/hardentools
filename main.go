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

import (
	"fmt"
	"os"

	"github.com/lxn/walk"
	. "github.com/lxn/walk/declarative"
	"golang.org/x/sys/windows/registry"
)

// allHardenSubjects contains all top level harden subjects that should
// be considered
var allHardenSubjects = []HardenInterface{
	// WSH.
	WSH,
	// Office.
	OfficeOLE,
	OfficeMacros,
	OfficeActiveX,
	OfficeDDE,
	// PDF.
	AdobePDFJS,
	AdobePDFObjects,
	AdobePDFProtectedMode,
	AdobePDFProtectedView,
	AdobePDFEnhancedSecurity,
	// Autorun.
	Autorun,
	// PowerShell.
	PowerShell,
	// UAC.
	UAC,
	// Explorer.
	FileAssociations,
	// Windows 10 / 1709 ASR
	//WindowsASR,
}

var expertConfig map[string]bool
var expertCompWidgetArray []Widget

var window *walk.MainWindow
var events *walk.TextEdit
var progress *walk.ProgressBar

const hardentoolsKeyPath = "SOFTWARE\\Security Without Borders\\"

func checkStatus() bool {
	key, err := registry.OpenKey(registry.CURRENT_USER, hardentoolsKeyPath, registry.READ)
	if err != nil {
		return false
	}
	defer key.Close()

	value, _, err := key.GetIntegerValue("Harden")
	if err != nil {
		return false
	}

	if value == 1 {
		return true
	}

	return false
}

func markStatus(hardened bool) {
	key, _, err := registry.CreateKey(registry.CURRENT_USER, hardentoolsKeyPath, registry.WRITE)
	if err != nil {
		panic(err)
	}
	defer key.Close()

	if hardened {
		key.SetDWordValue("Harden", 1)
	} else {
		key.SetDWordValue("Harden", 0)
	}
}

func hardenAll() {
	triggerAll(true)
	markStatus(true)

	walk.MsgBox(window, "Done!", "I have hardened all risky features!\nFor all changes to take effect please restart Windows.", walk.MsgBoxIconInformation)
	os.Exit(0)
}

func restoreAll() {
	triggerAll(false)
	markStatus(false)

	walk.MsgBox(window, "Done!", "I have restored all risky features!\nFor all changes to take effect please restart Windows.", walk.MsgBoxIconExclamation)
	os.Exit(0)
}

func triggerAll(harden bool) {
	if harden {
		events.AppendText("Now we are hardening ")
	} else {
		events.AppendText("Now we are restoring ")
	}

	for _, hardenSubject := range allHardenSubjects {
		if expertConfig[hardenSubject.Name()] == true {
			events.AppendText(fmt.Sprintf("%s, ", hardenSubject.Name()))

			err := hardenSubject.Harden(harden)

			if err != nil {
				events.AppendText(fmt.Sprintf("!! Operation for %s FAILED !!\n", hardenSubject.Name()))
				fmt.Println(fmt.Sprintf("Error for operation %s:", hardenSubject.Name()), err, "\n")
			}
		}
	}

	events.AppendText("\n")

	progress.SetValue(100)

	showStatus()

}

func showStatus() {
	for _, hardenSubject := range allHardenSubjects {
		if hardenSubject.IsHardened() {
			events.AppendText(fmt.Sprintf("%s is now hardened\n", hardenSubject.Name()))
		} else {
			events.AppendText(fmt.Sprintf("%s is now NOT hardened\n", hardenSubject.Name()))
		}
	}
}

func main() {
	var labelText, buttonText, eventsText string
	var buttonFunc func()
	var status = checkStatus()

	/// TEST
	/*	err := ShellExecute("runas", "notepad.exe", "/help")
		if err != nil {
			fmt.Fprintf(os.Stderr, "error running program: %v\n", err)
			os.Exit(1)
		}*/
	// Elevated rights are needed by: UAC, PowerShell, FileAssociations, Autorun

	// build up expert settings checkboxes and map
	expertConfig = make(map[string]bool)
	expertCompWidgetArray = make([]Widget, len(allHardenSubjects))
	var checkBoxArray = make([]*walk.CheckBox, len(allHardenSubjects))

	for i, hardenSubject := range allHardenSubjects {
		var subjectIsHardened = hardenSubject.IsHardened()

		if status == false {
			expertConfig[hardenSubject.Name()] = true // all checkboxes enabled by default in case of hardening
		} else {
			expertConfig[hardenSubject.Name()] = subjectIsHardened // only checkboxes enabled which are hardenend
		}

		expertCompWidgetArray[i] = CheckBox{
			AssignTo:         &checkBoxArray[i],
			Name:             hardenSubject.Name(),
			Text:             hardenSubject.LongName(),
			Checked:          expertConfig[hardenSubject.Name()],
			OnCheckedChanged: walk.EventHandler(checkBoxEventGenerator(i, hardenSubject.Name())),
			Enabled:          !(status && !subjectIsHardened) || !status,
		}
	}

	if status == false {
		buttonText = "Harden!"
		buttonFunc = hardenAll
		labelText = "Ready to harden some features of your system?"
	} else {
		buttonText = "Restore..."
		buttonFunc = restoreAll
		labelText = "We have already hardened some risky features, do you want to restore them?"
	}

	MainWindow{
		AssignTo: &window,
		Title:    "HardenTools - Security Without Borders",
		MinSize:  Size{500, 600},
		Layout:   VBox{},
		DataBinder: DataBinder{
			DataSource: expertConfig,
			AutoSubmit: true,
		},
		Children: []Widget{
			Label{Text: labelText},
			PushButton{
				Text:      buttonText,
				OnClicked: buttonFunc,
			},
			ProgressBar{
				AssignTo: &progress,
			},
			TextEdit{
				AssignTo: &events,
				Text:     eventsText,
				ReadOnly: true,
				MinSize:  Size{500, 250},
			},
			HSpacer{},
			HSpacer{},
			Label{Text: "Expert Settings - change only if you now what you are doing!"},
			Composite{
				Layout:   Grid{Columns: 3},
				Border:   true,
				Children: expertCompWidgetArray,
			},
		},
	}.Create()

	window.Run()
}

// generates a function that is used as an walk.EventHandler for the expert CheckBoxes
func checkBoxEventGenerator(n int, hardenSubjName string) func() {
	var i = n
	var hardenSubjectName = hardenSubjName
	return func() {
		fmt.Print("checkboxstatuschanged: ", i, " ", hardenSubjectName)
		x := *(expertCompWidgetArray[i]).(CheckBox).AssignTo
		isChecked := x.CheckState()
		expertConfig[hardenSubjectName] = (isChecked == walk.CheckChecked)
		fmt.Println(" expertConfig = ", expertConfig[hardenSubjectName])
	}
}
