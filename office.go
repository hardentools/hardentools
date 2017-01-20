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
	"fmt"
	"os"

	"golang.org/x/sys/windows/registry"
	//    "encoding/hex"
)

func check(e error) {
	if e != nil {
		panic(e)
	}
}

var office_versions = []string{
	"12.0", // Office 2007
	"14.0", // Office 2010
	"15.0", // Office 2013
	"16.0", // Office 2016
}

var office_apps = []string{"Excel", "PowerPoint", "Word"}

// Office Packager Objects

/*
0 - No prompt from Office when user clicks, object executes
1 - Prompt from Office when user clicks, object executes
2 - No prompt, Object does not execute
*/

func trigger_ole(enable bool) {
	var value uint32

	if enable {
		// Enable Packager
		events.AppendText("* Enabling Office Packager Objects\n")
		value = 1
	} else {
		// Disable Packager
		events.AppendText("* Disabling Office Packager Objects\n")
		value = 2
	}

	for _, office_version := range office_versions {
		for _, office_app := range office_apps {
			path := fmt.Sprintf("SOFTWARE\\Microsoft\\Office\\%s\\%s\\Security", office_version, office_app)
			//key, value = registry.Open
			key, _ := registry.OpenKey(registry.CURRENT_USER, path, registry.WRITE)
			key.SetDWordValue("PackagerPrompt", value)
			key.Close()
		}
	}
}

// Office Macros

/*
1 - Enable all
2 - Disable with notification
3 - Digitally signed only
4 - Disable all
*/

func trigger_macro(enable bool) {
	var f *os.File
	var err error

	var value uint32
	if enable {
		// Enable Macro
		events.AppendText("* Enabling Office Macros\n")
		value = 2
	} else {
		// Disable Macro
		events.AppendText("* Disabling Office Macros\n")
		value = 4
	}

	// Open file for registry backup
	f, err = os.Create("hardentools_office_macros_bkp.reg")
	check(err)
	defer f.Close()
	header := "Windows Registry Editor Version 5.00\n"
	_, err = f.WriteString(header)
	check(err)

	for _, office_version := range office_versions {
		for _, office_app := range office_apps {

			// TODO: Should we leave Excel enabled?
			path := fmt.Sprintf("SOFTWARE\\Microsoft\\Office\\%s\\%s\\Security", office_version, office_app)

			// backup current settings to .reg file
			if enable {
				pathRegEdit := "\n[HKEY_CURRENT_USER\\" + path + "]\n"
				var oldValue uint64
				var err error
				keyOrg, _ := registry.OpenKey(registry.CURRENT_USER, path, registry.READ)
				oldValue, _, err = keyOrg.GetIntegerValue("VBAWarnings")
				if err == nil {
					//fmt.Println("Old value of ", path, " = ", oldValue)
					value := pathRegEdit + "\"VBAWarnings\"=dword:" + fmt.Sprintf("%08x", oldValue)
					fmt.Println(value)
					_, err := f.WriteString(value)
					check(err)
				}
				keyOrg.Close()
			}

			key, _ := registry.OpenKey(registry.CURRENT_USER, path, registry.WRITE)
			key.SetDWordValue("VBAWarnings", value)
			key.Close()
		}
	}
	_, err = f.WriteString("\n")
	check(err)
}

// ActiveX

func trigger_activex(enable bool) {

	key, _, _ := registry.CreateKey(registry.CURRENT_USER, "SOFTWARE\\Microsoft\\Office\\Common\\Security", registry.WRITE)

	if enable {
		// Enable ActiveX
		events.AppendText("* Enabling ActiveX in Office\n")
		key.DeleteValue("DisableAllActiveX")
	} else {
		// Disable ActiveX
		events.AppendText("* Disabling ActiveX in Office\n")
		key.SetDWordValue("DisableAllActiveX", 1)
	}
	key.Close()
}
