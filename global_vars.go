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

package main

import "log"

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
	OneNoteBlockExtensions,
}
var hardenSubjectsForPrivilegedUsers = append(hardenSubjectsForUnprivilegedUsers, []HardenInterface{
	Autorun,
	PowerShell,
	Cmd,
	UAC,
	FileAssociations,
	WindowsASR,
	LSA,
	PUA,
	LibreOfficeMacroSecurityLevel,
	LibreOfficeHyperlinksWithCtrlClick,
	LibreOfficeBlockUntrustedRefererLinks,
	LibreOfficeUpdateCheck,
	LibreOfficeDisableUpdateLink,
}...)

var expertConfig map[string]bool

// Loggers for log output (we only need info and trace, errors have to be
// displayed in the GUI).
var (
	Trace *log.Logger // set this logger to get trace level verbosity logging output
	Info  *log.Logger // set this logger to get standard logging output
)
