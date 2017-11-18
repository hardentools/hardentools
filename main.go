// Hardentools
// Copyright (C) 2017  Security Without Borders
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
	"fmt"
	"github.com/lxn/walk"
	. "github.com/lxn/walk/declarative"
	"golang.org/x/sys/windows/registry"
	"os"
)

type ExpertConfig struct {
	// WSH.
	WSH bool
	// Office.
	OfficeOLE     bool
	OfficeMacros  bool
	OfficeActiveX bool
	OfficeDDE     bool
	// PDF.
	PDFJS               bool
	PDFObjects          bool
	PDFProtectedMode    bool
	PDFProtectedView    bool
	PDFEnhancedSecurity bool
	// Autorun.
	Autorun bool
	// PowerShell.
	PowerShell bool
	// UAC.
	UAC bool
	// Explorer.
	FileAssociations bool
}

var expertConfig = &ExpertConfig{true, true, true, true, true, true, true, true, true, true, true, true, true, true}

var window *walk.MainWindow
var events *walk.TextEdit
var progress *walk.ProgressBar

const hardentoolsKeyPath = "SOFTWARE\\Security Without Borders\\"

func checkStatus() bool {
	key, err := registry.OpenKey(registry.CURRENT_USER, hardentoolsKeyPath, registry.READ)
	if err != nil {
		return false
	}

	value, _, err := key.GetIntegerValue("Harden")
	if err != nil {
		return false
	}

	if value == 1 {
		return true
	}

	return false
}

func markStatus(hardened bool) {
	key, _, err := registry.CreateKey(registry.CURRENT_USER, hardentoolsKeyPath, registry.WRITE)
	if err != nil {
		panic(err)
	}

	if hardened {
		key.SetDWordValue("Harden", 1)
	} else {
		key.SetDWordValue("Harden", 0)
	}
}

func hardenAll() {
	triggerAll(true)
	markStatus(true)

	walk.MsgBox(window, "Done!", "I have hardened all risky features!\nFor all changes to take effect please restart Windows.", walk.MsgBoxIconInformation)
	os.Exit(0)
}

func restoreAll() {
	triggerAll(false)
	markStatus(false)

	walk.MsgBox(window, "Done!", "I have restored all risky features!\nFor all changes to take effect please restart Windows.", walk.MsgBoxIconExclamation)
	os.Exit(0)
}

func triggerAll(harden bool) {
	// WSH.
	if expertConfig.WSH {
		triggerWSH(harden)
	}
	// Office.
	if expertConfig.OfficeOLE {
		OfficeOLE.harden(harden)
	}
	if expertConfig.OfficeMacros {
		OfficeMacros.harden(harden)
	}
	if expertConfig.OfficeActiveX {
		OfficeActiveX.harden(harden)
	}
	if expertConfig.OfficeDDE {
		OfficeDDE.harden(harden)
	}
	// PDF.
	if expertConfig.PDFJS {
		triggerPDFJS(harden)
	}
	if expertConfig.PDFObjects {
		triggerPDFObjects(harden)
	}
	if expertConfig.PDFProtectedMode {
		triggerPDFProtectedMode(harden)
	}
	if expertConfig.PDFProtectedView {
		triggerPDFProtectedView(harden)
	}
	if expertConfig.PDFEnhancedSecurity {
		triggerPDFEnhancedSecurity(harden)
	}
	// Autorun.
	if expertConfig.Autorun {
		triggerAutorun(harden)
	}
	// PowerShell.
	if expertConfig.PowerShell {
		triggerPowerShell(harden)
	}
	// UAC.
	if expertConfig.UAC {
		UAC.harden(harden)
	}
	// Explorer.
	if expertConfig.FileAssociations {
		triggerFileAssociation(harden)
	}

	showStatus()

	progress.SetValue(100)
}

func showStatus() {
	events.AppendText(fmt.Sprintf("OLE hardened? %t\n", OfficeOLE.isHardened()))
	//		expertConfig.OfficeDDE = OfficeDDE.isHardened()
	//		expertConfig.OfficeActiveX = OfficeActiveX.isHardened()
	//		expertConfig.OfficeMacros = OfficeMacros.isHardened()

}

func main() {
	var labelText, buttonText, eventsText string
	var buttonFunc func()
	var status = checkStatus()

	if status == false {
		buttonText = "Harden!"
		buttonFunc = hardenAll
		labelText = "Ready to harden some features of your system?"
	} else {
		buttonText = "Restore..."
		buttonFunc = restoreAll
		labelText = "We have already hardened some risky features, do you want to restore them?"
		expertConfig.OfficeOLE = OfficeOLE.isHardened()
		expertConfig.OfficeDDE = OfficeDDE.isHardened()
		expertConfig.OfficeActiveX = OfficeActiveX.isHardened()
		expertConfig.OfficeMacros = OfficeMacros.isHardened()
		expertConfig.UAC = UAC.isHardened()
	}

	MainWindow{
		AssignTo: &window,
		Title:    "HardenTools - Security Without Borders",
		MinSize:  Size{600, 500},
		Layout:   VBox{},
		DataBinder: DataBinder{
			DataSource: expertConfig,
			AutoSubmit: true,
		},
		Children: []Widget{
			Label{Text: labelText},
			PushButton{
				Text:      buttonText,
				OnClicked: buttonFunc,
			},
			ProgressBar{
				AssignTo: &progress,
			},
			TextEdit{
				AssignTo: &events,
				Text:     eventsText,
				ReadOnly: true,
				MinSize:  Size{500, 250},
			},
			HSpacer{},
			HSpacer{},
			Label{Text: "Expert Settings - change only if you now what you are doing!"},
			Composite{
				Layout: Grid{Columns: 3},
				Border: true,
				Children: []Widget{
					CheckBox{
						Name:    "wshCB",
						Text:    "Windows Script Host",
						Checked: Bind("WSH"),
					},
					CheckBox{
						Name:    "officeOleCB",
						Text:    "Office Packager Objects (OLE)",
						Checked: Bind("OfficeOLE"),
						Enabled: !(status && !OfficeOLE.isHardened()) || !status,
					},
					CheckBox{
						Name:    "OfficeMacros",
						Text:    "Office Macros",
						Checked: Bind("OfficeMacros"),
						Enabled: !(status && !OfficeMacros.isHardened()) || !status,
					},
					CheckBox{
						Name:    "OfficeActiveX",
						Text:    "Office ActiveX",
						Checked: Bind("OfficeActiveX"),
						Enabled: !(status && !OfficeActiveX.isHardened()) || !status,
					},
					CheckBox{
						Name:    "OfficeDDE",
						Text:    "Office DDE  Links",
						Checked: Bind("OfficeDDE"),
						Enabled: !(status && !OfficeDDE.isHardened()) || !status,
					},
					CheckBox{
						Name:    "PDFJS",
						Text:    "Acrobat Reader JavaScript",
						Checked: Bind("PDFJS"),
					},
					CheckBox{
						Name:    "PDFObjects",
						Text:    "Acrobat Reader Embedded Objects",
						Checked: Bind("PDFObjects"),
					},
					CheckBox{
						Name:    "PDFProtectedMode",
						Text:    "Acrobat Reader ProtectedMode",
						Checked: Bind("PDFProtectedMode"),
					},
					CheckBox{
						Name:    "PDFProtectedView",
						Text:    "Acrobat Reader ProtectedView",
						Checked: Bind("PDFProtectedView"),
					},
					CheckBox{
						Name:    "PDFEnhancedSecurity",
						Text:    "Acrobat Reader Enhanced Security",
						Checked: Bind("PDFEnhancedSecurity"),
					},
					CheckBox{
						Name:    "Autorun",
						Text:    "AutoRun and AutoPlay",
						Checked: Bind("Autorun"),
					},
					CheckBox{
						Name:    "UAC",
						Text:    "UAC Prompt",
						Checked: Bind("UAC"),
						Enabled: !(status && !UAC.isHardened()) || !status,
					},
					CheckBox{
						Name:    "FileAssociations",
						Text:    "File associations",
						Checked: Bind("FileAssociations"),
					},
					CheckBox{
						Name:    "PowerShell",
						Text:    "Powershell and cmd",
						Checked: Bind("PowerShell"),
					},
				},
			},
		},
	}.Create()

	window.Run()
}
