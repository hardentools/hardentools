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
	"fmt"
	"io"
	"log"
	"os"

	"fyne.io/fyne"
	"fyne.io/fyne/app"
	"fyne.io/fyne/theme"

	"golang.org/x/sys/windows/registry"
)

// global configuration constants
const hardentoolsKeyPath = "SOFTWARE\\Security Without Borders\\"
const logpath = "hardentools.log"
const defaultLogLevel = "Trace"

// allHardenSubjects contains all top level harden subjects that should
// be considered
// Elevated rights are needed by: UAC, PowerShell, FileAssociations, Autorun, WindowsASR
var allHardenSubjects = []HardenInterface{}
var allHardenSubjectsWithAndWithoutElevatedPrivileges = []HardenInterface{
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
	// cmd.exe.
	Cmd,
	// UAC.
	UAC,
	// Explorer.
	FileAssociations,
	ShowFileExt,
	// Windows 10 / 1709 ASR
	WindowsASR,
	LSA,
}
var allHardenSubjectsForUnprivilegedUsers = []HardenInterface{
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
}

// Loggers for log output (we only need info and trace, errors have to be
// displayed in the GUI)
var (
	Trace *log.Logger
	Info  *log.Logger
)

var mainWindow fyne.Window
var expertConfig map[string]bool

// initLogging inits loggers
func initLogging(traceHandle io.Writer, infoHandle io.Writer) {
	Trace = log.New(traceHandle,
		"TRACE: ",
		log.Ldate|log.Ltime|log.Lshortfile)

	Info = log.New(infoHandle,
		"INFO: ",
		log.Ldate|log.Ltime|log.Lshortfile)
}

// checkStatus checks status of hardentools registry key
// (that tells if user environment is hardened / not hardened)
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

// markStatus sets hardentools status registry key
// (that tells if user environment is hardened / not hardened)
func markStatus(hardened bool) {

	if hardened {
		key, _, err := registry.CreateKey(registry.CURRENT_USER, hardentoolsKeyPath, registry.ALL_ACCESS)
		if err != nil {
			Info.Println(err.Error())
			panic(err)
		}
		defer key.Close()

		// set value that states that we have hardened the system
		err = key.SetDWordValue("Harden", 1)
		if err != nil {
			Info.Println(err.Error())
			showErrorDialog("Could not set hardentools registry keys - restore will not work!")
			panic(err)
		}
	} else {
		// on restore delete all hardentools registry keys afterwards
		err := registry.DeleteKey(registry.CURRENT_USER, hardentoolsKeyPath)
		if err != nil {
			Info.Println(err.Error())
			PrintEvent("Could not remove hardentools registry keys - nothing to worry about.\r\n")
		}
	}
}

// hardenAll starts harden procedure
func hardenAll() {
	showEventsTextArea()

	// use goroutine to allow lxn/walk to update window
	go func() {
		triggerAll(true)
		markStatus(true)
		showStatus()

		showInfoDialog("Done!\nAll risky features have been hardened!\n" +
			"For all changes to take effect, please restart Windows.")
		os.Exit(0)
	}()
}

// restoreAll starts restore procedure
func restoreAll() {
	showEventsTextArea()

	// use goroutine to allow lxn/walk to update window
	go func() {
		triggerAll(false)
		restoreSavedRegistryKeys()
		markStatus(false)
		showStatus()

		showInfoDialog("Done!\nI have restored all risky features!\nFor all changes to take effect please restart Windows.")
		os.Exit(0)
	}()
}

// triggerAll is used for harden and restore, depending on the harden parameter
// harden == true => harden
// harden == false => restore
// triggerAll evaluates the expertConfig settings and hardens/restores only
// the active items
func triggerAll(harden bool) {
	var outputString string
	if harden {
		PrintEvent("Now we are hardening ")
		outputString = "Hardening"
	} else {
		PrintEvent("Now we are restoring ")
		outputString = "Restoring"
	}

	Trace.Println(outputString)

	for _, hardenSubject := range allHardenSubjects {
		if expertConfig[hardenSubject.Name()] == true {
			PrintEvent(fmt.Sprintf("%s, ", hardenSubject.Name()))

			err := hardenSubject.Harden(harden)
			if err != nil {
				PrintEvent(fmt.Sprintf("\r\n!! %s %s FAILED !!\r\n", outputString, hardenSubject.Name()))
				Info.Printf("Error for operation %s: %s", hardenSubject.Name(), err.Error())
			} else {
				Trace.Printf("%s %s has been successful", outputString, hardenSubject.Name())
			}
		}
	}

	PrintEvent("\r\n")
}

// hardenDefaultsAgain restores the original settings and
// hardens using the default settings (no custom settings apply)
func hardenDefaultsAgain() {
	showEventsTextArea()

	// use goroutine to allow lxn/walk to update window
	go func() {
		// restore hardened settings
		triggerAll(false)
		restoreSavedRegistryKeys()
		markStatus(false)

		// reset expertConfig (is set to currently already hardened settings
		// in case of restore)
		expertConfig = make(map[string]bool)
		for _, hardenSubject := range allHardenSubjects {
			expertConfig[hardenSubject.Name()] = hardenSubject.HardenByDefault()
		}

		// harden all settings
		triggerAll(true)
		markStatus(true)

		showInfoDialog("Done!\nI have hardened all risky features!\nFor all changes to take effect please restart Windows.")
		os.Exit(0)
	}()
}

// showStatus iterates all harden subjects and prints status of each
// (checks real status on system)
func showStatus() {
	for _, hardenSubject := range allHardenSubjects {
		if hardenSubject.IsHardened() {
			eventText := fmt.Sprintf("%s is now hardened\r\n", hardenSubject.Name())
			PrintEvent(eventText)
			Info.Print(eventText)
		} else {
			eventText := fmt.Sprintf("%s is now NOT hardened\r\n", hardenSubject.Name())
			PrintEvent(eventText)
			Info.Print(eventText)
		}
	}
}

// main method for hardentools
func main() {
	// init main window
	appl := app.New()
	appl.Settings().SetTheme(theme.LightTheme())
	mainWindow = appl.NewWindow("Hardentools")
	mainWindow.Resize(fyne.NewSize(700, 400))
	mainWindow.SetFixedSize(true)

	go main2()
	mainWindow.ShowAndRun()
}
