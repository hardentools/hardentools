// Hardentools
// Copyright (C) 2018  Security Without Borders
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

/*
// some C code for managing elevated privileges
#include <windows.h>
#include <shellapi.h>

// checks if we are running with elevated privileges (admin rights)
int IsElevated( ) {
    boolean fRet = FALSE;
    HANDLE hToken = NULL;
    if( OpenProcessToken( GetCurrentProcess( ),TOKEN_QUERY,&hToken ) ) {
        TOKEN_ELEVATION Elevation;
        DWORD cbSize = sizeof( TOKEN_ELEVATION );
        if( GetTokenInformation( hToken, TokenElevation, &Elevation, sizeof( Elevation ), &cbSize ) ) {
            fRet = Elevation.TokenIsElevated;
        }
    }
    if( hToken ) {
        CloseHandle( hToken );
    }
    if( fRet ){
		return 1;
	}
	else {
		return 0;
	}
}

// executes the executable in the current directory (or in path) with "runas"
// to aquire admin privileges
int ExecuteWithRunas(char execName[]){
	SHELLEXECUTEINFO shExecInfo;

	shExecInfo.cbSize = sizeof(SHELLEXECUTEINFO);

	shExecInfo.fMask = 0x00008000;
	shExecInfo.hwnd = NULL;
	shExecInfo.lpVerb = "runas";
	shExecInfo.lpFile = execName;
	shExecInfo.lpParameters = NULL;
	shExecInfo.lpDirectory = NULL;
	shExecInfo.nShow = SW_NORMAL;
	shExecInfo.hInstApp = NULL;

	boolean success = ShellExecuteEx(&shExecInfo);
	if (success)
		return 1;
	else
		return 0;
}
*/
import "C"

import (
	"fmt"
	"io"
	"log"
	"os"

	"golang.org/x/sys/windows/registry"
)

// global configuration constants
const hardentoolsKeyPath = "SOFTWARE\\Security Without Borders\\"
const logpath = "hardentools.log"
const defaultLogLevel = "Info"

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
	// UAC.
	UAC,
	// Explorer.
	FileAssociations,
	ShowFileExt,
	// Windows 10 / 1709 ASR
	WindowsASR,
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

var expertConfig map[string]bool

// Loggers for log output (we only need info and trace, errors have to be
// displayed in the GUI)
var (
	Trace *log.Logger
	Info  *log.Logger
)

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
			events.AppendText("Could not remove hardentools registry keys - nothing to worry about.")
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

		showInfoDialog("Done!\nI have hardened all risky features!\nFor all changes to take effect please restart Windows.")
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
		events.AppendText("Now we are hardening ")
		outputString = "Hardening"
	} else {
		events.AppendText("Now we are restoring ")
		outputString = "Restoring"
	}

	for _, hardenSubject := range allHardenSubjects {
		if expertConfig[hardenSubject.Name()] == true {
			events.AppendText(fmt.Sprintf("%s, ", hardenSubject.Name()))

			err := hardenSubject.Harden(harden)
			if err != nil {
				events.AppendText(fmt.Sprintf("\n!! %s %s FAILED !!\n", outputString, hardenSubject.Name()))
				Info.Printf("Error for operation %s: %s", hardenSubject.Name(), err.Error())
			} else {
				Trace.Printf("%s %s has been successful", outputString, hardenSubject.Name())
			}
		}
	}

	events.AppendText("\n")
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
		// in case of restore
		expertConfig = make(map[string]bool)
		for _, hardenSubject := range allHardenSubjects {
			// TODO: sets all harden subjects to active for now. Better: replace
			// this with default settings (to be implemented)
			expertConfig[hardenSubject.Name()] = true
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
			eventText := fmt.Sprintf("%s is now hardened\n", hardenSubject.Name())
			events.AppendText(eventText)
			Info.Print(eventText)
		} else {
			eventText := fmt.Sprintf("%s is now NOT hardened\n", hardenSubject.Name())
			events.AppendText(eventText)
			Info.Print(eventText)
		}
	}
}

// restartWithElevatedPrivileges tries to restart hardentools.exe with admin privileges
func restartWithElevatedPrivileges() {
	// find out our program (exe) name
	progName := os.Args[0]

	// start us again, this time with elevated privileges
	if C.ExecuteWithRunas(C.CString(progName)) == 1 {
		// exit this instance (the unprivileged one)
		os.Exit(0)
	} else {
		// something went wrong
		showErrorDialog("Error while trying to gain elevated privileges. Starting in unprivileged mode...")
	}
}

// main method for hardentools
func main() {
	// check if hardentools has been started with elevated rights. If not
	// ask user if he wants to elevate
	if C.IsElevated() == 0 {
		askElevationDialog()
	}
	elevationStatus := false
	if C.IsElevated() == 1 {
		elevationStatus = true
	}

	// show splash screen
	splashChannel := make(chan bool, 1)
	showSplash(splashChannel)

	openMainWindow(splashChannel, elevationStatus)
}
