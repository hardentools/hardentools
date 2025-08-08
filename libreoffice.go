// Hardentools
// Copyright (C) 2017-2025 Security Without Borders
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

// LibreOfficeMacroSecurityLevel sets MacroSecurityLevel and SecureURL
// for handling macros. SecureURL will be allowed to be set by user, while
// changing security level will not be allowed
// The following values are possible:
// - Low (All macros are allowed to be executed.) - 0
// - Medium (The user must confirm the execution of a macro). - 1
// - High (Signed macros may be executed.) - 2
// - Very High (Only macros from trusted locations may be executed). - 3
// Default value: High (2)
// Hardened value: Very high (3)
// Setting: org.openoffice.Office.Common/Security/Scripting/MacroSecurityLevel
var LibreOfficeMacroSecurityLevel = &RegistryMultiValue{
	ArraySingleSZ: []*RegistrySingleValueSZ{
		{
			RootKey:       registry.LOCAL_MACHINE,
			Path:          "SOFTWARE\\Policies\\LibreOffice\\org.openoffice.Office.Common\\Security\\Scripting\\MacroSecurityLevel",
			ValueName:     "Value",
			HardenedValue: "3",
			shortName:     "LibreOffice MacroSecurityLevel Value",
			description:   "Sets MacroSecurityLevel for LibreOffice to highest setting.",
		},
		{
			RootKey:       registry.LOCAL_MACHINE,
			Path:          "SOFTWARE\\Policies\\LibreOffice\\org.openoffice.Office.Common\\Security\\Scripting\\SecureURL",
			ValueName:     "Value",
			HardenedValue: "",
			shortName:     "LibreOffice SecureURL Value",
			description:   "Sets SecureURL to empty",
		},
	},
	ArraySingleDWORD: []*RegistrySingleValueDWORD{
		{
			RootKey:       registry.LOCAL_MACHINE,
			Path:          "SOFTWARE\\Policies\\LibreOffice\\org.openoffice.Office.Common\\Security\\Scripting\\MacroSecurityLevel",
			ValueName:     "Final",
			HardenedValue: 1,
			shortName:     "LibreOffice MacroSecurityLevel Final",
			description:   "Sets MacroSecurityLevel non-overwritable by user.",
		},
		{
			RootKey:       registry.LOCAL_MACHINE,
			Path:          "SOFTWARE\\Policies\\LibreOffice\\org.openoffice.Office.Common\\Security\\Scripting\\SecureURL",
			ValueName:     "Final",
			HardenedValue: 0,
			shortName:     "LibreOffice SecureURL Final",
			description:   "Sets SecureURL overwritable by user.",
		},
	},
	shortName: "LibreOffice Macro Security",
	longName:  "LibreOffice Macro Security",
	description: "Sets MacroSecurityLevel for LibreOffice to highest\n" +
		"level, which effectively disables Macros, except\n" +
		"you add some directories to the exception list.",
	hardenByDefault: false,
}

// LibreOfficeHyperlinksWithCtrlClick sets HyperlinksWithCtrlClick:
// If this option is enabled, one mouse click is not
// enough to follow a hyperlink. <Ctrl> must be held.
// Default value: Enabled (true)
// Hardened value: Enabled (true)
// Setting: org.openoffice.Office.Common/Security/Scripting/HyperlinksWithCtrlClick
var LibreOfficeHyperlinksWithCtrlClick = &RegistryMultiValue{
	ArraySingleSZ: []*RegistrySingleValueSZ{
		{
			RootKey:       registry.LOCAL_MACHINE,
			Path:          "SOFTWARE\\Policies\\LibreOffice\\org.openoffice.Office.Common\\Security\\Scripting\\HyperlinksWithCtrlClick",
			ValueName:     "Value",
			HardenedValue: "true",
			shortName:     "LibreOffice Hyperlinks with Ctrl-Click value",
			description:   "Requires Ctrl-Click to follow Hyperlinks.",
		},
	},
	ArraySingleDWORD: []*RegistrySingleValueDWORD{
		{
			RootKey:       registry.LOCAL_MACHINE,
			Path:          "SOFTWARE\\Policies\\LibreOffice\\org.openoffice.Office.Common\\Security\\Scripting\\HyperlinksWithCtrlClick",
			ValueName:     "Final",
			HardenedValue: 1,
			shortName:     "LibreOffice HyperlinksWithCtrlClick Final",
			description:   "Sets HyperlinksWithCtrlClick non-overwritable by user.",
		},
	},
	shortName: "LibreOffice Ctrl-Click Hyperlinks",
	longName:  "LibreOffice Ctrl-Click to follow Hyperlinks",
	description: "Requires Ctrl-Click to follow Hyperlinks for\n" +
		"LibreOffice (which is the default).",
	hardenByDefault: false,
}

// LibreOfficeBlockUntrustedRefererLinks set BlockUntrustedRefererLinks:
// Defines whether linked images from external sources may be retrieved. A
// corresponding restriction does not apply to documents stored in trusted
// locations. The option is only for images. This option does not restrict
// the retrieval of other media files or linked documents.
// Default value: Disabled
// Recommended value: Enabled
// Setting: org.openoffice.Office.Common/Security/Scripting/BlockUntrustedRefererLinks
var LibreOfficeBlockUntrustedRefererLinks = &RegistryMultiValue{
	ArraySingleSZ: []*RegistrySingleValueSZ{
		{
			RootKey:       registry.LOCAL_MACHINE,
			Path:          "SOFTWARE\\Policies\\LibreOffice\\org.openoffice.Office.Common\\Security\\Scripting\\BlockUntrustedRefererLinks",
			ValueName:     "Value",
			HardenedValue: "true",
			shortName:     "LibreOffice BlockUntrustedRefererLinks value",
			description:   "Blocks untrusted referer links.",
		},
	},
	ArraySingleDWORD: []*RegistrySingleValueDWORD{
		{
			RootKey:       registry.LOCAL_MACHINE,
			Path:          "SOFTWARE\\Policies\\LibreOffice\\org.openoffice.Office.Common\\Security\\Scripting\\BlockUntrustedRefererLinks",
			ValueName:     "Final",
			HardenedValue: 1,
			shortName:     "LibreOffice BlockUntrustedRefererLinks Final",
			description:   "Sets BlockUntrustedRefererLinks non-overwritable by user.",
		},
	},
	shortName:       "LibreOffice Block Untrusted Referer Links",
	longName:        "LibreOffice Block Untrusted Referer Links",
	description:     "Blocks untrusted referer links for images for LibreOffice.",
	hardenByDefault: false,
}

// LibreOfficeUpdateCheck sets two settings to enforce check for updates
// and corresponding notifications to users
// AutoCheckEnabled: Specifies whether to automatically check for available updates. The user will be is informed about available updates with a message. There is no automatic installation.
// Default value: Enabled ("true")
// Recommended value: Enabled ("true")
// Setting: org.openoffice.Office.Jobs/Jobs/org.openoffice.Office.Jobs:Job['UpdateCheck']/Arguments/AutoCheckEnabled
//
// CheckInterval: Defines the interval at which new updates should be checked
// for. The option has no function, if AutoCheckEnabled is disabled. This does
// currently not work via Registry, we keep it in anyhow, for the case that
// LibreOffice is extending Registry support.
// Default value: Every week
// Hardened value: Every day (86400)
// Setting: org.openoffice.Office.Jobs/Jobs/org.openoffice.Office.Jobs:Job['UpdateCheck']/Arguments/CheckInterval
//
// Note: CheckInterval seems not to work for LibreOffice 7.5.4
var LibreOfficeUpdateCheck = &RegistryMultiValue{
	ArraySingleSZ: []*RegistrySingleValueSZ{
		{
			RootKey:       registry.LOCAL_MACHINE,
			Path:          "SOFTWARE\\Policies\\LibreOffice\\org.openoffice.Office.Jobs\\Jobs\\org.openoffice.Office.Jobs:Job['UpdateCheck']\\Arguments\\AutoCheckEnabled",
			ValueName:     "Value",
			HardenedValue: "true",
			shortName:     "LibreOffice AutoCheckEnabled Value",
			description:   "Sets AutoCheckEnabled for LibreOffice",
		},
		{
			RootKey:       registry.LOCAL_MACHINE,
			Path:          "SOFTWARE\\Policies\\LibreOffice\\org.openoffice.Office.Jobs\\Jobs\\org.openoffice.Office.Jobs:Job['UpdateCheck']\\Arguments\\CheckInterval",
			ValueName:     "Value",
			HardenedValue: "86400",
			shortName:     "LibreOffice CheckInterval Value",
			description:   "Sets CheckInterval to 86400",
		},
	},
	ArraySingleDWORD: []*RegistrySingleValueDWORD{
		{
			RootKey:       registry.LOCAL_MACHINE,
			Path:          "SOFTWARE\\Policies\\LibreOffice\\org.openoffice.Office.Jobs\\Jobs\\org.openoffice.Office.Jobs:Job['UpdateCheck']\\Arguments\\CheckInterval",
			ValueName:     "Final",
			HardenedValue: 1,
			shortName:     "LibreOffice CheckInterval Final",
			description:   "Sets CheckInterval non-overwritable by user.",
		},
		{
			RootKey:       registry.LOCAL_MACHINE,
			Path:          "SOFTWARE\\Policies\\LibreOffice\\org.openoffice.Office.Jobs\\Jobs\\org.openoffice.Office.Jobs:Job['UpdateCheck']\\Arguments\\AutoCheckEnabled",
			ValueName:     "Final",
			HardenedValue: 1,
			shortName:     "LibreOffice AutoCheckEnabled Final",
			description:   "Sets AutoCheckEnabled non-overwritable by user.",
		},
	},
	shortName:       "LibreOffice Enforce Update Checks",
	longName:        "LibreOffice Enforce Update Checks",
	description:     "Enforces regular update checks for LibreOffice.",
	hardenByDefault: false,
}

// LibreOfficeDisableUpdateLink (Calc & Writer)
// Defines whether values from linked documents should be loaded automatically
// when the file is opened. This allows for example to include values from a
// spreadsheet/writer file into another file. Furthermore, it is also possible
// to load values via a network. In this case data can be transferred from the
// open document to another system. Hardentools disables all links.
// Settings:
// - org.openoffice.Office.Calc/Content/Update/Link
// - org.openoffice.Office.Writer/Content/Update/Link
var LibreOfficeDisableUpdateLink = &RegistryMultiValue{
	ArraySingleSZ: []*RegistrySingleValueSZ{
		{
			RootKey:       registry.LOCAL_MACHINE,
			Path:          "SOFTWARE\\Policies\\LibreOffice\\org.openoffice.Office.Calc\\Content\\Update\\Link",
			ValueName:     "Value",
			HardenedValue: "1",
			shortName:     "LibreOffice Calc Update Link Value",
			description:   "Sets Calc Update Link for LibreOffice",
		},
		{
			RootKey:       registry.LOCAL_MACHINE,
			Path:          "SOFTWARE\\Policies\\LibreOffice\\org.openoffice.Office.Writer\\Content\\Update\\Link",
			ValueName:     "Value",
			HardenedValue: "0",
			shortName:     "LibreOffice Writer Update Link Value",
			description:   "Sets Writer Update Link for LibreOffice",
		},
	},
	ArraySingleDWORD: []*RegistrySingleValueDWORD{
		{
			RootKey:       registry.LOCAL_MACHINE,
			Path:          "SOFTWARE\\Policies\\LibreOffice\\org.openoffice.Office.Calc\\Content\\Update\\Link",
			ValueName:     "Final",
			HardenedValue: 1,
			shortName:     "LibreOffice Calc Update Link Final",
			description:   "Sets Calc Update Link setting non-overwritable by user.",
		},
		{
			RootKey:       registry.LOCAL_MACHINE,
			Path:          "SOFTWARE\\Policies\\LibreOffice\\org.openoffice.Office.Writer\\Content\\Update\\Link",
			ValueName:     "Final",
			HardenedValue: 1,
			shortName:     "LibreOffice Writer Update Link Final",
			description:   "Sets Writer Update Link setting non-overwritable by user.",
		},
	},
	shortName: "LibreOffice Disable Links",
	longName:  "LibreOffice Disable Updates from Links",
	description: "Disables updates from linked documents for LibreOffice\n" +
		"Writer and Calc documents upon opening a file. This\n" +
		"prevents stealing of data using malicious documents.\n" +
		"Note: Does not work for Writer as of today\n" +
		" (latest test: LibreOffice 7.5.4)",
	hardenByDefault: false,
}
