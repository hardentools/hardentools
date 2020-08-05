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
	"io"
	"io/ioutil"
	"log"
	"os"
	"strings"

	"fyne.io/fyne"
	"fyne.io/fyne/app"
	"fyne.io/fyne/theme"
	"fyne.io/fyne/widget"

	"golang.org/x/sys/windows/registry"
)

// Global configuration constants.
const hardentoolsKeyPath = "SOFTWARE\\Security Without Borders\\"
const logpath = "hardentools.log"
const defaultLogLevel = "Info"

// allHardenSubjects contains all top level harden subjects that should
// be considered.
// Elevated rights are needed by:
// UAC, PowerShell, FileAssociations, Autorun, WindowsASR
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
// displayed in the GUI).
var (
	Trace *log.Logger
	Info  *log.Logger
)

var mainWindow fyne.Window
var expertConfig map[string]bool

// initLogging initializes loggers.
func initLogging(traceHandle io.Writer, infoHandle io.Writer) {
	Trace = log.New(traceHandle,
		"TRACE: ",
		log.Ldate|log.Ltime|log.Lshortfile)

	Info = log.New(infoHandle,
		"INFO: ",
		log.Ldate|log.Ltime|log.Lshortfile)

	log.SetOutput(infoHandle)
}

// checkStatus checks status of hardentools registry key
// (that tells if user environment is hardened / not hardened).
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
// (that tells if user environment is hardened / not hardened).
func markStatus(hardened bool) {

	if hardened {
		key, _, err := registry.CreateKey(registry.CURRENT_USER, hardentoolsKeyPath, registry.ALL_ACCESS)
		if err != nil {
			Info.Println(err.Error())
			panic(err)
		}
		defer key.Close()

		// Set value that states that we have hardened the system.
		err = key.SetDWordValue("Harden", 1)
		if err != nil {
			Info.Println(err.Error())
			showErrorDialog("Could not set hardentools registry keys - restore will not work!")
			panic(err)
		}
	} else {
		// On restore delete all hardentools registry keys afterwards.
		err := registry.DeleteKey(registry.CURRENT_USER, hardentoolsKeyPath)
		if err != nil {
			Info.Println(err.Error())
			ShowFailure("Remove hardentools registry keys", "Could not remove")
		}
	}
}

// hardenAll starts harden procedure.
func hardenAll() {
	showEventsTextArea()

	// use goroutine to allow gui to update window
	go func() {
		triggerAll(true)
		markStatus(true)
		showStatus()

		showEndDialog("Done!\nRisky features have been hardened!\nFor all changes to take effect please restart Windows.")
		os.Exit(0)
	}()
}

// RestoreAll starts restore procedure.
func restoreAll() {
	showEventsTextArea()

	// Use goroutine to allow gui to update window.
	go func() {
		triggerAll(false)
		restoreSavedRegistryKeys()
		markStatus(false)
		showStatus()

		showEndDialog("Done!\nRestored settings to their original state.\nFor all changes to take effect please restart Windows.")
		os.Exit(0)
	}()
}

// triggerAll is used for harden and restore, depending on the harden parameter.
// harden == true => harden
// harden == false => restore
// triggerAll evaluates the expertConfig settings and hardens/restores only
// the active items.
func triggerAll(harden bool) {
	var outputString string
	if harden {
		//PrintEvent("Now we are hardening ")
		outputString = "Hardening"
	} else {
		//PrintEvent("Now we are restoring ")
		outputString = "Restoring"
	}

	Trace.Println(outputString)

	for _, hardenSubject := range allHardenSubjects {
		if expertConfig[hardenSubject.Name()] == true {

			err := hardenSubject.Harden(harden)
			if err != nil {
				ShowFailure(hardenSubject.Name(), err.Error())
				Info.Printf("Error for operation %s: %s", hardenSubject.Name(), err.Error())
			} else {
				ShowSuccess(hardenSubject.Name())
				Trace.Printf("%s %s has been successful", outputString, hardenSubject.Name())
			}
		}
	}
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

// showStatus iterates all harden subjects and prints status of each
// (checks real status on system).
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

// Main method for hardentools.
func main() {
	// Parse command line parameters/flags.
	flag.String("log-level", defaultLogLevel, "Info|Trace: enables logging with verbosity; Off: disables logging")
	flag.Parse()
	flag.VisitAll(func(f *flag.Flag) {
		// Only supports log-level right now.
		if f.Name == "log-level" {
			// Init logging.
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
				// Off.
				initLogging(ioutil.Discard, ioutil.Discard)
			}
		}
	})

	// Init main window.
	appl := app.New()
	appl.Settings().SetTheme(theme.LightTheme())
	mainWindow = appl.NewWindow("Hardentools")
	// emptyContainer needed to get minimum window size to be able to show
	// (elevation) dialog.
	emptyContainer := widget.NewScrollContainer(widget.NewVBox())
	emptyContainer.SetMinSize(fyne.NewSize(700, 300))
	mainWindow.SetContent(emptyContainer)
	// TODO
	// mainWindow.SetIcon()

	Trace.Println("Starting up hardentools")

	go mainGUI()

	mainWindow.ShowAndRun()
}
