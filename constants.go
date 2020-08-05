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

const (
	hardentoolsKeyPath            = "SOFTWARE\\Security Without Borders\\"
	logPath                       = "hardentools.log"
	defaultLogLevel               = "Info"
	explorerPoliciesKey           = "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer"
	explorerDisallowRunKey        = "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\DisallowRun"
	errorRestoreDisallowRunFailed = "Fully restoring DisableRun settings failed"
)
