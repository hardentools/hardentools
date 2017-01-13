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
    "golang.org/x/sys/windows/registry"
    "github.com/lxn/walk"
    . "github.com/lxn/walk/declarative"
)

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
    trigger_ole(false)
    trigger_macro(false)
    trigger_pdf_js(false)
    trigger_pdf_objects(false)

    mark_status(true)
}

func enable_all() {
    trigger_wsh(true)
    trigger_ole(true)
    trigger_macro(true)
    trigger_pdf_js(true)
    trigger_pdf_objects(true)

    mark_status(false)    
}

func main() {
    var window *walk.MainWindow
    var events *walk.TextEdit
    var button_text, events_text string
    var button_func func()

    if check_status() == false {
        button_text = "Harden!"
        button_func = disable_all
        events_text = "Ready to harden some features of your system?"
    } else {
        button_text = "Restore..."
        button_func = enable_all
        events_text = "We have already hardened some risky features, do you want to restore them?"
    }

    MainWindow{
        AssignTo: &window,
        Title: "Harden - Security Without Borders",
        MinSize: Size{400, 300},
        Layout:  VBox{},
        Children: []Widget{
            TextEdit{
                AssignTo: &events,
                Text: events_text,
                ReadOnly: true,
            },
            PushButton{
                Text: button_text,
                OnClicked: button_func,
            },
        },
    }.Create()

    window.Run()
}
