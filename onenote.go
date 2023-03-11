// Hardentools
// Copyright (C) 2023 Security Without Borders
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
	"golang.org/x/sys/windows/registry"
)

// OneNoteBlockExtensions blocks certain types of files in OneNote client
var OneNoteBlockExtensions = &OfficeRegistryRegExSingleDWORD{
	RootKey:         registry.CURRENT_USER,
	PathRegEx:       "SOFTWARE\\Microsoft\\Office\\%s\\%s\\Options",
	ValueName:       "DisableEmbeddedFiles",
	HardenedValue:   1,
	OfficeApps:      []string{"onenote"},
	OfficeVersions:  standardOfficeVersions,
	shortName:       "OneNote Attachments",
	longName:        "Block OneNote Attachments",
	description:     "Disables opening of attachments in OneNote",
	hardenByDefault: true,
}
