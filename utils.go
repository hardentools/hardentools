// Hardentools
// Copyright (C) 2017-2022 Security Without Borders
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

/*
// some C code for managing elevated privileges
#include <windows.h>
#include <shellapi.h>

// Checks if we are running with elevated privileges (admin rights).
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

// Executes the executable in the current directory (or in path) with "runas"
// to aquire admin privileges.
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
	"unsafe"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"strings"
	"syscall"

	"golang.org/x/sys/windows/registry"
)

// isElevated verifies if program is running with admin privileges
func isElevated() bool {
	isElevated := C.IsElevated()
	if isElevated == 1 {
		return true
	}
	return false
}

// startWithElevatedPrivs starts progName with elevated privileges
func startWithElevatedPrivs(progName string) bool {
	cprogname := C.CString(progName)
	defer C.free(unsafe.Pointer(cprogname))
	ret := C.ExecuteWithRunas(cprogname)
	if ret == 1 {
		return true
	}
	return false
}

// Helper method for executing cmd commands (does not open cmd window).
func executeCommand(cmd string, args ...string) (string, error) {
	var out []byte
	command := exec.Command(cmd, args...)
	command.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	out, err := command.CombinedOutput()

	return string(out), err
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

func cmdHardenRestore(harden bool) {
	// check if hardentools has been started with elevated rights.
	elevationStatus := isElevated()
	if elevationStatus {
		Info.Println("Started with elevated rights")
		allHardenSubjects = hardenSubjectsForPrivilegedUsers
	} else {
		Info.Println("Started without elevated rights")
		allHardenSubjects = hardenSubjectsForUnprivilegedUsers
	}

	// TODO: verify if hardening has been done with elevate privileges and now restoring
	// should be done without elevated privileges (needs additional registry key)

	// check hardening status
	status := checkStatus()
	if status == false && harden == false {
		fmt.Println("Not hardened. Please harden before restoring.")
		os.Exit(-1)
	} else if status == true && harden == true {
		fmt.Println("Already hardened. Please restore before hardening again.")
		os.Exit(-1)
	}

	// build up expert settings checkboxes and map
	expertConfig = make(map[string]bool)
	for _, hardenSubject := range allHardenSubjects {
		var subjectIsHardened = hardenSubject.IsHardened()
		//var enableField bool

		if status == false {
			// harden only settings which are not hardened yet
			expertConfig[hardenSubject.Name()] = !subjectIsHardened && hardenSubject.HardenByDefault()
		} else {
			// restore only hardened settings
			expertConfig[hardenSubject.Name()] = subjectIsHardened
		}
	}

	triggerAll(harden)
	if !harden {
		restoreSavedRegistryKeys()
	}
	markStatus(harden)
	showStatus()
}

// initLogging initializes loggers.
func initLogging(traceHandle io.Writer, infoHandle io.Writer, guiVersion bool) {
	if guiVersion {
		Trace = log.New(traceHandle, "TRACE: ", log.Lshortfile)
		Info = log.New(infoHandle, "INFO: ", log.Lshortfile)
	} else {
		Trace = log.New(traceHandle, "", 0)
		Info = log.New(infoHandle, "", 0)
	}
	log.SetOutput(infoHandle)
}

// initLoggingWithCmdParameters initializes logging considering if cli version specifics
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
		initLogging(ioutil.Discard, logfile, !cmd)
	} else if strings.EqualFold(*logLevelPtr, "Trace") {
		// standard + trace logging
		initLogging(logfile, logfile, !cmd)
	} else if strings.EqualFold(*logLevelPtr, "Off") {
		// no logging
		initLogging(ioutil.Discard, ioutil.Discard, !cmd)
	} else {
		// default logging (only standard log output)
		initLogging(ioutil.Discard, logfile, !cmd)
	}
}
