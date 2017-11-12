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
	"github.com/lxn/walk"
	. "github.com/lxn/walk/declarative"
	"golang.org/x/sys/windows/registry"
	"os"
)


type ExpertConfig struct {
	// WSH.
	WSH bool
	// Office.
	OfficeOLE int
	OfficeMacros int
	OfficeActiveX int
	OfficeDDE int
	// PDF.
	PDFJS int
	PDFObjects int
	PDFProtectedMode int
	PDFProtectedView int
	PDFEnhancedSecurity int
	// Autorun.
	Autorun int
	// PowerShell.
	PowerShell int
	// UAC.
	UAC int
	// Explorer.
	FileAssociations int
}

var expertConfig = &ExpertConfig{ true, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1 }

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
	if expertConfig.WSH { triggerWSH(harden) }
	// Office.
	if expertConfig.OfficeOLE == 1 { triggerOfficeOLE(harden) }
	if expertConfig.OfficeMacros == 1 { triggerOfficeMacros(harden) }
	if expertConfig.OfficeActiveX == 1 { triggerOfficeActiveX(harden) }
	if expertConfig.OfficeDDE == 1 { triggerOfficeDDE(harden) }
	// PDF.
	if expertConfig.PDFJS == 1 { triggerPDFJS(harden) }
	if expertConfig.PDFObjects == 1 { triggerPDFObjects(harden) }
	if expertConfig.PDFProtectedMode == 1 { triggerPDFProtectedMode(harden) }
	if expertConfig.PDFProtectedView == 1 { triggerPDFProtectedView(harden) }
	if expertConfig.PDFEnhancedSecurity == 1 { triggerPDFEnhancedSecurity(harden) }
	// Autorun.
	if expertConfig.Autorun == 1 { triggerAutorun(harden) }
	// PowerShell.
	if expertConfig.PowerShell == 1 { triggerPowerShell(harden) }
	// UAC.
	if expertConfig.UAC == 1 { triggerUAC(harden) }
	// Explorer.
	if expertConfig.FileAssociations == 1 { triggerFileAssociation(harden) }

	progress.SetValue(100)
}

func main() {
	var labelText, buttonText, eventsText string
	var buttonFunc func()


	if checkStatus() == false {
		buttonText = "Harden!"
		buttonFunc = hardenAll
		labelText = "Ready to harden some features of your system?"
	} else {
		buttonText = "Restore..."
		buttonFunc = restoreAll
		labelText = "We have already hardened some risky features, do you want to restore them?"
	}

	MainWindow{
		AssignTo: &window,
		Title:    "HardenTools - Security Without Borders",
		MinSize:  Size{600, 600},
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
				MinSize: Size{500,300},
			},
			VSplitter{
				Children: []Widget{
					// WSH
					HSplitter{
						Children: []Widget{
							/*Label{
								Text:    "Consider WSH",
								Enabled: Bind("wshB1.Checked"),
							},*/
							// RadioButtonGroup is needed for data binding only.
							CheckBox{
								Name:    "wshB1",
								Text:    "Windows Scripting Host",
								Checked: Bind("WSH"),
							},
							/*RadioButtonGroup{
								DataMember: "WSH",
								Buttons: []RadioButton{
									RadioButton{
										Name:  "wshB1",
										Text:  "Yes",
										Value: 1,
									},
									RadioButton{
										Name:  "wshB2",
										Text:  "No",
										Value: 0,
									},
								},
							},*/
						},
					},
					// OfficeOLE
					HSplitter{
						Children: []Widget{
							Label{
								Text:    "Consider Office OLE",
								Enabled: Bind("officeOLEB1.Checked"),
							},
							RadioButtonGroup{
								DataMember: "OfficeOLE",
								Buttons: []RadioButton{
									RadioButton{
										Name:  "officeOLEB1",
										Text:  "Yes",
										Value: 1,
									},
									RadioButton{
										Name:  "officeOLEB2",
										Text:  "No",
										Value: 0,
									},
								},
							},
						},
					},
					// OfficeMacros
					HSplitter{
						Children: []Widget{
							Label{
								Text:    "Consider Office Macros",
								Enabled: Bind("officeMacrosB1.Checked"),
							},
							RadioButtonGroup{
								DataMember: "OfficeMacros",
								Buttons: []RadioButton{
									RadioButton{
										Name:  "officeMacrosB1",
										Text:  "Yes",
										Value: 1,
									},
									RadioButton{
										Name:  "officeMacrosB2",
										Text:  "No",
										Value: 0,
									},
								},
							},
						},
					},
					// OfficeActiveX
					HSplitter{
						Children: []Widget{
							Label{
								Text:    "Consider Office ActiveX",
								Enabled: Bind("officeActiveXB1.Checked"),
							},
							RadioButtonGroup{
								DataMember: "OfficeActiveX",
								Buttons: []RadioButton{
									RadioButton{
										Name:  "officeActiveXB1",
										Text:  "Yes",
										Value: 1,
									},
									RadioButton{
										Name:  "officeActiveXB2",
										Text:  "No",
										Value: 0,
									},
								},
							},
						},
					},
					// OfficeDDE
					HSplitter{
						Children: []Widget{
							Label{
								Text:    "Consider Office DDE",
								Enabled: Bind("officeDDEB1.Checked"),
							},
							RadioButtonGroup{
								DataMember: "OfficeDDE",
								Buttons: []RadioButton{
									RadioButton{
										Name:  "officeDDEB1",
										Text:  "Yes",
										Value: 1,
									},
									RadioButton{
										Name:  "officeDDEB2",
										Text:  "No",
										Value: 0,
									},
								},
							},
						},
					},
/*
	PDFJS int
	PDFObjects int
	PDFProtectedMode int
	PDFProtectedView int
	PDFEnhancedSecurity int
	// Autorun.
	Autorun int

	// UAC.
	UAC int
	// Explorer.
	FileAssociations int*/
					// PowerShell
					HSplitter{
						Children: []Widget{
							Label{
								Text:    "Disable Powershell and cmd.exe",
								Enabled: Bind("cmdB1.Checked"),
							},
							RadioButtonGroup{
								DataMember: "PowerShell",
								Buttons: []RadioButton{
									RadioButton{
										Name:  "cmdB1",
										Text:  "Yes",
										Value: 1,
									},
									RadioButton{
										Name:  "cmdB2",
										Text:  "No",
										Value: 0,
									},
								},
							},
						},
					},
				},
			},
		},
	}.Create()

	window.Run()
}
