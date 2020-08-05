// Hardentools
// Copyright (C) 2017-2020 Security Without Borders
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
	"os/exec"
	"syscall"
)

// Helper method for executing cmd commands (does not open cmd window).
func executeCommand(cmd string, args ...string) (string, error) {
	var out []byte
	command := exec.Command(cmd, args...)
	command.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	out, err := command.CombinedOutput()

	return string(out), err
}
