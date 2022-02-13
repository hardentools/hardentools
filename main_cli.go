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

//go:build cli

package main

import (
	"flag"
	"fmt"
)

// Main method for hardentools.
func main() {
	fmt.Println("Welcome to the command line version of hardentools.")
	// parse command line parameters/flags
	logLevelPtr := flag.String("log-level", defaultLogLevel, "\"Info\": Enables logging with standard verbosity; \"Trace\": Verbose logging; \"Off\": Disables logging")
	restorePtr := flag.Bool("restore", false, "restore")
	hardenPtr := flag.Bool("harden", false, "harden with default settings")
	flag.Parse()

	status := checkStatus()
	if status {
		if *restorePtr == true {
			initLoggingWithCmdParameters(logLevelPtr, true)
			cmdRestore()
		} else {
			fmt.Println("System is currently hardened. Use parameter -restore to restore to not hardened state.")
		}
	} else {
		if *hardenPtr == true {
			initLoggingWithCmdParameters(logLevelPtr, true)
			cmdHarden()
		} else {
			fmt.Println("System is currently NOT hardened. Use parameter -harden to harden system.")
		}
	}
}

// showStatus iterates all harden subjects and prints status of each
// (checks real status on system)
func showStatus() {
	for _, hardenSubject := range allHardenSubjects {
		if hardenSubject.IsHardened() {
			eventText := fmt.Sprintf("%s is now hardened\r\n", hardenSubject.Name())
			Info.Print(eventText)
		} else {
			eventText := fmt.Sprintf("%s is now NOT hardened\r\n", hardenSubject.Name())
			Info.Print(eventText)
		}
	}
}
