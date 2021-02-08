// Hardentools
// Copyright (C) 2017-2021 Security Without Borders
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
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"strings"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"

	"golang.org/x/sys/windows/registry"
)

func init() {
	// Tries to prevent DLL preloading/sideloading for dynamically loaded
	// DLLs (loaded by fyne.io and dependencies)
	SaferDLLLoading()
}

// allHardenSubjects contains all top level harden subjects that should
// be considered.
var allHardenSubjects = []HardenInterface{}
var hardenSubjectsForUnprivilegedUsers = []HardenInterface{
	WSH,
	OfficeOLE,
	OfficeMacros,
	OfficeActiveX,
	OfficeDDE,
	AdobePDFJS,
	AdobePDFObjects,
	AdobePDFProtectedMode,
	AdobePDFProtectedView,
	AdobePDFEnhancedSecurity,
	ShowFileExt,
}
var hardenSubjectsForPrivilegedUsers = append(hardenSubjectsForUnprivilegedUsers, []HardenInterface{
	Autorun,
	PowerShell,
	Cmd,
	UAC,
	FileAssociations,
	WindowsASR,
	LSA,
}...)

var mainWindow fyne.Window
var expertConfig map[string]bool

// Loggers for log output (we only need info and trace, errors have to be
// displayed in the GUI).
var (
	Trace *log.Logger // set this logger to get trace level verbosity logging output
	Info  *log.Logger // set this logger to get standard logging output
)

// initLogging initializes loggers.
func initLogging(traceHandle io.Writer, infoHandle io.Writer) {
	Trace = log.New(traceHandle, "TRACE: ", log.Lshortfile)
	Info = log.New(infoHandle, "INFO: ", log.Lshortfile)
	log.SetOutput(infoHandle)
}

// checkStatus checks status of hardentools registry key
// (that tells if user environment is hardened / not hardened).
func checkStatus() bool {
	key, err := registry.OpenKey(registry.CURRENT_USER, hardentoolsKeyPath,
		registry.READ)
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
		key, _, err := registry.CreateKey(registry.CURRENT_USER,
			hardentoolsKeyPath, registry.ALL_ACCESS)
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

	// Use goroutine to allow gui to update window.
	go func() {
		triggerAll(true)
		markStatus(true)
		showStatus(false)

		showEndDialog("Done! Risky features have been hardened!\nFor all changes to take effect please restart Windows.")
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
		showStatus(false)

		showEndDialog("Done! Restored settings to their original state.\nFor all changes to take effect please restart Windows.")
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
		Info.Println("Now we are hardening...")
		outputString = "Hardening"
	} else {
		Info.Println("Now we are restoring...")
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
		showStatus(false)

		showEndDialog("Done!\nRisky features have been hardened!\nFor all changes to take effect please restart Windows.")
		os.Exit(0)
	}()
}

// showStatus iterates all harden subjects and prints status of each
// (checks real status on system)
func showStatus(commandline bool) {
	for _, hardenSubject := range allHardenSubjects {
		if hardenSubject.IsHardened() {
			eventText := fmt.Sprintf("%s is now hardened\r\n", hardenSubject.Name())
			if !commandline {
				ShowIsHardened(hardenSubject.Name())
			}
			Info.Print(eventText)
		} else {
			eventText := fmt.Sprintf("%s is now NOT hardened\r\n", hardenSubject.Name())
			if !commandline {
				ShowNotHardened(hardenSubject.Name())
			}
			Info.Print(eventText)
		}
	}
}

// Main method for hardentools.
func main() {
	// parse command line parameters/flags
	logLevelPtr := flag.String("log-level", defaultLogLevel, "\"Info\": Enables logging with standard verbosity; \"Trace\": Verbose logging; \"Off\": Disables logging")
	restorePtr := flag.Bool("restore", false, "restore without GUI (command line only)")
	hardenPtr := flag.Bool("harden", false, "harden without GUI, only default settings (command line only)")
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
	appl := app.New()
	appl.Settings().SetTheme(theme.LightTheme())
	mainWindow = appl.NewWindow("Hardentools")
	// emptyContainer needed to get minimum window size to be able to show
	// (elevation) dialog.
	emptyContainer := container.NewVScroll(widget.NewLabel(""))
	emptyContainer.SetMinSize(fyne.NewSize(700, 300))
	mainWindow.SetContent(emptyContainer)
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

func initLoggingWithCmdParameters(logLevelPtr *string, cmd bool) {
	var logfile *os.File
	var err error

	if cmd {
		// command line only => use stdout
		logfile = os.Stdout
	} else {
		// UI => use logfile
		logfile, err = os.Create(logPath)
		if err != nil {
			panic(err)
		}
	}
	if strings.EqualFold(*logLevelPtr, "Info") {
		// only standard log output
		initLogging(ioutil.Discard, logfile)
	} else if strings.EqualFold(*logLevelPtr, "Trace") {
		// standard + trace logging
		initLogging(logfile, logfile)
	} else if strings.EqualFold(*logLevelPtr, "Off") {
		// no logging
		initLogging(ioutil.Discard, ioutil.Discard)
	} else {
		// default logging (only standard log output)
		initLogging(ioutil.Discard, logfile)
	}
}
