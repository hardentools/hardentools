/*
    Hardentools
    Copyright (C) 2017  Claudio Guarnieri, Mariano Graziano

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

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

func disable_all() {
    trigger_wsh(false)
    progress.SetValue(14)
    trigger_ole(false)
    progress.SetValue(24)
    trigger_macro(false)
    progress.SetValue(42)
    trigger_activex(false)
    progress.SetValue(56)
    trigger_pdf_js(false)
    progress.SetValue(70)
    trigger_pdf_objects(false)
    progress.SetValue(84)
    trigger_autorun(false)
    progress.SetValue(100)

    mark_status(true)

    walk.MsgBox(window, "Done!", "I have disabled all risky features!", walk.MsgBoxIconInformation)
    os.Exit(0)
}

func restore_all() {
    trigger_wsh(true)
    progress.SetValue(14)
    trigger_ole(true)
    progress.SetValue(24)
    trigger_macro(true)
    progress.SetValue(42)
    trigger_activex(true)
    progress.SetValue(56)
    trigger_pdf_js(true)
    progress.SetValue(70)
    trigger_pdf_objects(true)
    progress.SetValue(84)
    trigger_autorun(true)
    progress.SetValue(100)

    mark_status(false)

    walk.MsgBox(window, "Done!", "I have restored all risky features!", walk.MsgBoxIconExclamation)
    os.Exit(0)  
}

func main() {
    var label_text, button_text, events_text string
    var button_func func()

    if check_status() == false {
        button_text = "Harden!"
        button_func = disable_all
        label_text = "Ready to harden some features of your system?"
    } else {
        button_text = "Restore..."
        button_func = restore_all
        label_text = "We have already hardened some risky features, do you want to restore them?"
    }

    MainWindow{
        AssignTo: &window,
        Title:    "Harden - Security Without Borders",
        MinSize:  Size{400, 300},
        Layout:   VBox{},
        Children: []Widget{
            Label{Text: label_text},
            PushButton{
                Text:      button_text,
                OnClicked: button_func,
            },
            ProgressBar{
                AssignTo: &progress,
            },
            TextEdit{
                AssignTo: &events,
                Text:     events_text,
                ReadOnly: true,
            },
        },
    }.Create()

    window.Run()
}
