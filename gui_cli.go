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
	"os"
)

// showErrorDialog shows an error message.
func showErrorDialog(errorMessage string) {
	Info.Println("Error: " + errorMessage)
}

// showInfoDialog shows an info message.
func showInfoDialog(infoMessage string) {
	Info.Println("Information: " + infoMessage)
}

// ShowSuccess sets GUI status of name field to success
func ShowSuccess(name string) {
	Info.Println(name + ": Success")
}

// ShowFailure sets GUI status of name field to failureText
func ShowFailure(name, failureText string) {
	Info.Println(name + " failed with error: " + failureText)
}

func cmdHarden() {
	cmdHardenRestore(true)

	Info.Println("Done! Risky features have been hardened!\nFor all changes to take effect please restart Windows.")
	os.Exit(0)
}

func cmdRestore() {
	cmdHardenRestore(false)

	Info.Println("Done! Restored settings to their original state.\nFor all changes to take effect please restart Windows.")
	os.Exit(0)
}
