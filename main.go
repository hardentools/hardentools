// Hardentools
// Copyright (C) 2017-2023 Security Without Borders
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
	"encoding/base64"
	"flag"
	"fmt"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
)

func init() {
	// Tries to prevent DLL preloading/sideloading for dynamically loaded
	// DLLs (loaded by fyne.io and dependencies)
	SaferDLLLoading()
}

var mainWindow fyne.Window
var appl fyne.App

// Main method for hardentools.
func main() {
	// parse command line parameters/flags
	logLevelPtr := flag.String("log-level", defaultLogLevel, "\"Info\": Enables logging with standard verbosity; \"Trace\": Verbose logging; \"Off\": Disables logging")
	restorePtr := flag.Bool("restore", false, "restore in command line mode")
	hardenPtr := flag.Bool("harden", false, "harden with default settings in command line mode")
	flag.Parse()

	if *hardenPtr == true {
		// no GUI, just harden with default settings
		initLoggingWithCmdParameters(logLevelPtr, true)
		cmdHarden()
	}
	if *restorePtr == true {
		// no GUI, just restore
		initLoggingWithCmdParameters(logLevelPtr, true)
		cmdRestore()
	}

	initLoggingWithCmdParameters(logLevelPtr, false)

	// Init main window.
	appl = app.New()
	appl.Settings().SetTheme(theme.LightTheme())
	mainWindow = appl.NewWindow("Hardentools")

	// Show splash screen since loading takes some time (at least with admin
	// privileges) due to sequential reading of all the settings.
	progressBar := widget.NewProgressBarInfinite()
	progressBar.Show()
	splashContainer := container.NewVScroll(container.NewVBox(
		widget.NewLabelWithStyle("Hardentools is starting up. Please wait...", fyne.TextAlignCenter, fyne.TextStyle{Monospace: true}),
		progressBar))

	// make room for elevation dialog
	splashContainer.SetMinSize(fyne.NewSize(700, 300))

	mainWindow.SetContent(splashContainer)
	// set window icon
	iconContent, _ := base64.StdEncoding.DecodeString(IconBase64)
	var windowIcon = HardentoolsWindowIconStruct{
		"HardentoolsWindowIcon",
		iconContent,
	}
	mainWindow.SetIcon(windowIcon)

	Trace.Println("Starting up hardentools")

	go mainGUI()

	mainWindow.ShowAndRun()
}

// showStatus iterates all harden subjects and prints status of each
// (checks real status on system)
func showStatus() {
	for _, hardenSubject := range allHardenSubjects {
		if hardenSubject.IsHardened() {
			eventText := fmt.Sprintf("%s is now hardened\r\n", hardenSubject.Name())
			ShowIsHardened(hardenSubject.Name())
			Info.Print(eventText)
		} else {
			eventText := fmt.Sprintf("%s is now NOT hardened\r\n", hardenSubject.Name())
			ShowNotHardened(hardenSubject.Name())
			Info.Print(eventText)
		}
	}
}
