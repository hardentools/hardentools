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
	"github.com/lxn/walk"
	. "github.com/lxn/walk/declarative"
	"golang.org/x/sys/windows/registry"
	"os"
)

var window *walk.MainWindow
var events *walk.TextEdit
var progress *walk.ProgressBar

const hardentoolsKey = "SOFTWARE\\Security Without Borders\\"

func checkStatus() bool {
	key, err := registry.OpenKey(registry.CURRENT_USER, hardentoolsKey, registry.READ)
	if err != nil {
		return false
	}

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
	key, _, err := registry.CreateKey(registry.CURRENT_USER, hardentoolsKey, registry.WRITE)
	if err != nil {
		panic(err)
	}

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
	// WSH.
	triggerWSH(harden)
	// Office.
	triggerOfficeOLE(harden)
	triggerOfficeMacros(harden)
	triggerOfficeActiveX(harden)
	// PDF.
	triggerPDFJS(harden)
	triggerPDFObjects(harden)
	triggerPDFProtectedMode(harden)
	triggerPDFProtectedView(harden)
	triggerPDFEnhancedSecurity(harden)
	// Autorun.
	triggerAutorun(harden)
	// PowerShell.
	triggerPowerShell(harden)
	// UAC.
	triggerUAC(harden)
	// Explorer.
	triggerFileAssociation(harden)

	progress.SetValue(100)
}

func main() {
	var labelText, buttonText, eventsText string
	var buttonFunc func()

	if checkStatus() == false {
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
		Title:    "Harden - Security Without Borders",
		MinSize:  Size{400, 300},
		Layout:   VBox{},
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
			},
		},
	}.Create()

	window.Run()
}
