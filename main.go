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
	"os"
	"github.com/lxn/walk"
	"golang.org/x/sys/windows/registry"
	. "github.com/lxn/walk/declarative"
)

var window *walk.MainWindow
var events *walk.TextEdit
var progress *walk.ProgressBar

const harden_key_path = "SOFTWARE\\Security Without Borders\\"

func check_status() bool {
	key, err := registry.OpenKey(registry.CURRENT_USER, harden_key_path, registry.READ)
	if err != nil {
		return false
	}

	value, _, err := key.GetIntegerValue("Harden")
	if err != nil {
		return false
	}

	if value == 1 {
		return true
	} else {
		return false
	}
}

func mark_status(is_active bool) {
	key, _, err := registry.CreateKey(registry.CURRENT_USER, harden_key_path, registry.WRITE)
	if err != nil {
		panic(err)
	}

	if is_active {
		key.SetDWordValue("Harden", 1)
	} else {
		key.SetDWordValue("Harden", 0)
	}
}

func harden_all() {
	var harden bool = true

	trigger_all(harden)

	mark_status(harden)

	walk.MsgBox(window, "Done!", "I have hardened all risky features!\nFor all changes to take effect please restart Windows.", walk.MsgBoxIconInformation)
	os.Exit(0)
}

func restore_all() {
	var harden bool = false

	trigger_all(harden)

	mark_status(harden)

	walk.MsgBox(window, "Done!", "I have restored all risky features!\nFor all changes to take effect please restart Windows.", walk.MsgBoxIconExclamation)
	os.Exit(0)  
}

func trigger_all(harden bool) {
	trigger_wsh(harden)
	progress.SetValue(12)
	trigger_ole(harden)
	progress.SetValue(30)
	trigger_macro(harden)
	progress.SetValue(36)
	trigger_activex(harden)
	progress.SetValue(48)
	trigger_pdf_js(harden)
	progress.SetValue(60)
	trigger_pdf_objects(harden)
	progress.SetValue(72)
	trigger_autorun(harden)
	progress.SetValue(84)
	trigger_powershell(harden)
	progress.SetValue(90)
	trigger_uac(harden)
	progress.SetValue(95) 
	trigger_fileassoc(harden)
	progress.SetValue(100) 
}

func main() {
	var label_text, button_text, events_text string
	var button_func func()

	if check_status() == false {
		button_text = "Harden!"
		button_func = harden_all
		label_text = "Ready to harden some features of your system?"
	} else {
		button_text = "Restore..."
		button_func = restore_all
		label_text = "We have already hardened some risky features, do you want to restore them?"
	}

	MainWindow{
		AssignTo: &window,
		Title: "Harden - Security Without Borders",
		MinSize: Size{400, 300},
		Layout: VBox{},
		Children: []Widget{
			Label{Text: label_text},
			PushButton{
				Text: button_text,
				OnClicked: button_func,
			},
			ProgressBar{
				AssignTo: &progress,
			},
			TextEdit{
				AssignTo: &events,
				Text: events_text,
				ReadOnly: true,
			},
		},
	}.Create()

	window.Run()
}
