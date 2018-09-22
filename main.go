// Hardentools
// Copyright (C) 2018  Security Without Borders
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
// along with this program.  If not, see <http://wweventsDialog.gnu.org/licenses/>.

package main

/*
// some C code for managing elevated privileges
#include <windows.h>
#include <shellapi.h>

// checks if we are running with elevated privileges (admin rights)
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

// executes the executable in the current directory (or in path) with "runas"
// to aquire admin privileges
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
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"strings"

	"github.com/lxn/walk"
	"github.com/lxn/walk/declarative"
	"golang.org/x/sys/windows/registry"
)

// global configuration constants
const hardentoolsKeyPath = "SOFTWARE\\Security Without Borders\\"
const logpath = "hardentools.log"
const defaultLogLevel = "Info"

// allHardenSubjects contains all top level harden subjects that should
// be considered
// Elevated rights are needed by: UAC, PowerShell, FileAssociations, Autorun, WindowsASR
var allHardenSubjects = []HardenInterface{}
var allHardenSubjectsWithAndWithoutElevatedPrivileges = []HardenInterface{
	// WSH.
	WSH,
	// Office.
	OfficeOLE,
	OfficeMacros,
	OfficeActiveX,
	OfficeDDE,
	// PDF.
	AdobePDFJS,
	AdobePDFObjects,
	AdobePDFProtectedMode,
	AdobePDFProtectedView,
	AdobePDFEnhancedSecurity,
	// Autorun.
	Autorun,
	// PowerShell.
	PowerShell,
	// UAC.
	UAC,
	// Explorer.
	FileAssociations,
	ShowFileExt,
	// Windows 10 / 1709 ASR
	WindowsASR,
}
var allHardenSubjectsForUnprivilegedUsers = []HardenInterface{
	// WSH.
	WSH,
	// Office.
	OfficeOLE,
	OfficeMacros,
	OfficeActiveX,
	OfficeDDE,
	// PDF.
	AdobePDFJS,
	AdobePDFObjects,
	AdobePDFProtectedMode,
	AdobePDFProtectedView,
	AdobePDFEnhancedSecurity,
}

var expertConfig map[string]bool
var expertCompWidgetArray []declarative.Widget
var events *walk.TextEdit
var window *walk.MainWindow

// Loggers for log output (we only need info and trace, errors have to be
// displayed in the GUI)
var (
	Trace *log.Logger
	Info  *log.Logger
)

// initLogging inits loggers
func initLogging(traceHandle io.Writer, infoHandle io.Writer) {
	Trace = log.New(traceHandle,
		"TRACE: ",
		log.Ldate|log.Ltime|log.Lshortfile)

	Info = log.New(infoHandle,
		"INFO: ",
		log.Ldate|log.Ltime|log.Lshortfile)
}

// checkStatus checks status of hardentools registry key
// (that tells if user environment is hardened / not hardened)
func checkStatus() bool {
	key, err := registry.OpenKey(registry.CURRENT_USER, hardentoolsKeyPath, registry.READ)
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
// (that tells if user environment is hardened / not hardened)
func markStatus(hardened bool) {

	if hardened {
		key, _, err := registry.CreateKey(registry.CURRENT_USER, hardentoolsKeyPath, registry.ALL_ACCESS)
		if err != nil {
			Info.Println(err.Error())
			panic(err)
		}
		defer key.Close()

		// set value that states that we have hardened the system
		err = key.SetDWordValue("Harden", 1)
		if err != nil {
			Info.Println(err.Error())
			walk.MsgBox(nil, "ERROR", "Could not set hardentools registry keys - restore will not work!", walk.MsgBoxIconExclamation)
			panic(err)
		}
	} else {
		// on restore delete all hardentools registry keys afterwards
		err := registry.DeleteKey(registry.CURRENT_USER, hardentoolsKeyPath)
		if err != nil {
			Info.Println(err.Error())
			events.AppendText("Could not remove hardentools registry keys - nothing to worry about.")
		}
	}
}

// hardenAll starts harden procedure
func hardenAll() {
	showEventsTextArea()

	// use goroutine to allow lxn/walk to update window
	go func() {
		triggerAll(true)
		markStatus(true)

		walk.MsgBox(nil, "Done!", "I have hardened all risky features!\nFor all changes to take effect please restart Windows.", walk.MsgBoxIconInformation)
		os.Exit(0)
	}()
}

// restoreAll starts restore procedure
func restoreAll() {
	showEventsTextArea()

	// use goroutine to allow lxn/walk to update window
	go func() {
		triggerAll(false)
		markStatus(false)

		walk.MsgBox(nil, "Done!", "I have restored all risky features!\nFor all changes to take effect please restart Windows.", walk.MsgBoxIconExclamation)
		os.Exit(0)
	}()
}

// triggerAll is used for harden and restore, depending on the harden parameter
// harden == true => harden
// harden == false => restore
// triggerAll evaluates the expertConfig settings and hardens/restores only
// the active items
func triggerAll(harden bool) {
	var outputString string
	if harden {
		events.AppendText("Now we are hardening ")
		outputString = "Hardening"
	} else {
		events.AppendText("Now we are restoring ")
		outputString = "Restoring"
	}

	for _, hardenSubject := range allHardenSubjects {
		if expertConfig[hardenSubject.Name()] == true {
			events.AppendText(fmt.Sprintf("%s, ", hardenSubject.Name()))

			err := hardenSubject.Harden(harden)
			if err != nil {
				events.AppendText(fmt.Sprintf("\n!! %s %s FAILED !!\n", outputString, hardenSubject.Name()))
				Info.Printf("Error for operation %s: %s", hardenSubject.Name(), err.Error())
			} else {
				Info.Printf("%s %s has been successful", outputString, hardenSubject.Name())
			}
		}
	}

	events.AppendText("\n")
	showStatus()
}

// hardenDefaultsAgain restores the original settings and
// hardens using the default settings (no custom settings apply)
func hardenDefaultsAgain() {
	showEventsTextArea()

	// use goroutine to allow lxn/walk to update window
	go func() {
		// restore hardened settings
		triggerAll(false)
		markStatus(false)

		// reset expertConfig (is set to currently already hardened settings
		// in case of restore
		expertConfig = make(map[string]bool)
		for _, hardenSubject := range allHardenSubjects {
			// TODO: sets all harden subjects to active for now. Better: replace
			// this with default settings (to be implemented)
			expertConfig[hardenSubject.Name()] = true
		}

		// harden all settings
		triggerAll(true)
		markStatus(true)

		walk.MsgBox(nil, "Done!", "I have hardened all risky features!\nFor all changes to take effect please restart Windows.", walk.MsgBoxIconInformation)
		os.Exit(0)
	}()
}

// showStatus iterates all harden subjects and prints status of each
// (checks real status on system)
func showStatus() {
	for _, hardenSubject := range allHardenSubjects {
		if hardenSubject.IsHardened() {
			eventText := fmt.Sprintf("%s is now hardened\n", hardenSubject.Name())
			events.AppendText(eventText)
			Info.Print(eventText)
		} else {
			eventText := fmt.Sprintf("%s is now NOT hardened\n", hardenSubject.Name())
			events.AppendText(eventText)
			Info.Print(eventText)
		}
	}
}

// openMainWindows opens the main window
func openMainWindow(splashChannel chan bool) {
	// init variables
	var labelText, buttonText, eventsText, expertSettingsText string
	var enableHardenAdditionalButton bool
	var buttonFunc func()

	// check if we are running with elevated rights
	if C.IsElevated() == 0 {
		//runningWithElevatedPrivileges = false
		allHardenSubjects = allHardenSubjectsForUnprivilegedUsers
	} else {
		//runningWithElevatedPrivileges = true
		allHardenSubjects = allHardenSubjectsWithAndWithoutElevatedPrivileges
	}

	// check hardening status
	var status = checkStatus()

	// parse command line parameters/flags
	flag.String("log-level", defaultLogLevel, "Info|Trace: enables logging with verbosity; Off: disables logging")
	flag.Parse()
	flag.VisitAll(func(f *flag.Flag) {
		//fmt.Printf("%s = \"%s\"\n", f.Name, f.Value.String())
		// only supports log-level right now
		if f.Name == "log-level" {
			// Init logging
			if strings.EqualFold(f.Value.String(), "Info") {
				var logfile, err = os.Create(logpath)
				if err != nil {
					panic(err)
				}

				initLogging(ioutil.Discard, logfile)
			} else if strings.EqualFold(f.Value.String(), "Trace") {
				var logfile, err = os.Create(logpath)
				if err != nil {
					panic(err)
				}

				initLogging(logfile, logfile)
			} else {
				// Off
				initLogging(ioutil.Discard, ioutil.Discard)
			}
		}
	})

	// build up expert settings checkboxes and map
	expertConfig = make(map[string]bool)
	expertCompWidgetArray = make([]declarative.Widget, len(allHardenSubjects))
	var checkBoxArray = make([]*walk.CheckBox, len(allHardenSubjects))

	for i, hardenSubject := range allHardenSubjects {
		var subjectIsHardened = hardenSubject.IsHardened()
		var enableField bool

		if status == false {
			// all checkboxes checked by default, disabled only if subject is already hardened
			expertConfig[hardenSubject.Name()] = !subjectIsHardened

			// only enable, if not already hardenend
			enableField = !subjectIsHardened
		} else {
			// restore: only checkboxes checked which are hardenend
			expertConfig[hardenSubject.Name()] = subjectIsHardened

			// disable all, since the user must restore all settings because otherwise
			// consecutive execution of hardentools might fail (e.g. starting powershell
			// or cmd commands) or might be ineffectiv (settings are already hardened) or
			// hardened settings might get saved as "before" settings, so user
			// can't revert to the state "before"
			enableField = false
		}

		expertCompWidgetArray[i] = declarative.CheckBox{
			AssignTo:         &checkBoxArray[i],
			Name:             hardenSubject.Name(),
			Text:             hardenSubject.LongName(),
			Checked:          expertConfig[hardenSubject.Name()],
			OnCheckedChanged: walk.EventHandler(checkBoxEventGenerator(i, hardenSubject.Name())),
			Enabled:          enableField,
		}
	}

	// set labels / text fields (harden or restore)
	if status == false {
		buttonText = "Harden!"
		buttonFunc = hardenAll
		labelText = "Ready to harden some features of your system?"
		expertSettingsText = "Expert Settings - change only if you now what you are doing! Disabled settings are already hardened."
		enableHardenAdditionalButton = false
	} else {
		buttonText = "Restore..."
		buttonFunc = restoreAll
		labelText = "We have already hardened some risky features, do you want to restore them?"
		expertSettingsText = "The following hardened features are going to be restored:"
		enableHardenAdditionalButton = true
	}

	// build up main GUI window
	//	window
	declarative.MainWindow{
		AssignTo: &window,
		Title:    "HardenTools - Security Without Borders",
		//MinSize:  declarative.Size{500, 600},
		Layout: declarative.VBox{},
		DataBinder: declarative.DataBinder{
			DataSource: expertConfig,
			AutoSubmit: true,
		},
		Children: []declarative.Widget{
			declarative.HSpacer{},
			declarative.PushButton{
				Text:      "Harden again (all default settings)",
				OnClicked: hardenDefaultsAgain,
				Visible:   enableHardenAdditionalButton,
			},
			declarative.HSpacer{},
			declarative.Label{Text: labelText},
			declarative.PushButton{
				Text:      buttonText,
				OnClicked: buttonFunc,
			},
			declarative.HSpacer{},
			declarative.Label{Text: expertSettingsText},
			declarative.Composite{
				Layout:   declarative.Grid{Columns: 3},
				Border:   true,
				Children: expertCompWidgetArray,
			},
			declarative.TextEdit{
				AssignTo: &events,
				Text:     eventsText,
				ReadOnly: true,
				MinSize:  declarative.Size{500, 450},
				Visible:  false,
			},
		},
	}.Create()

	// hide splash screen
	splashChannel <- true

	// start main GUI
	window.Run()
}

// checkBoxEventGenerator generates a function that is used as an walk.EventHandler
// for the expert CheckBoxes in main GUI
func checkBoxEventGenerator(n int, hardenSubjName string) func() {
	var i = n
	var hardenSubjectName = hardenSubjName
	return func() {
		x := *(expertCompWidgetArray[i]).(declarative.CheckBox).AssignTo
		isChecked := x.CheckState()
		expertConfig[hardenSubjectName] = (isChecked == walk.CheckChecked)
	}
}

// showSplash shows an splash screen during initialization
func showSplash(splashChannel chan bool) {
	var splashWindow *walk.MainWindow
	declarative.MainWindow{
		AssignTo: &splashWindow,
		Title:    "HardenTools - HardenTools - Starting Up. Please wait.",
		MinSize:  declarative.Size{600, 100},
	}.Create()

	// wait for main gui, then hide splash
	go func() {
		<-splashChannel
		splashWindow.Hide()
	}()
}

// showEventsTextArea sets the events area to visible and disables action buttons
func showEventsTextArea() {
	// set the events text element to visible to display output
	events.SetVisible(true)

	// set all other items but the last (which is the events text element from
	// above) to disabled so no further action is possible by the user
	length := window.Children().Len()
	for i := 0; i < length-1; i++ {
		window.Children().At(i).SetEnabled(false)
	}
}

// showErrorDialog shows an error message
func showErrorDialog(errorMessage string) {
	var dialog *walk.Dialog
	var okPB *walk.PushButton
	_, err := declarative.Dialog{
		AssignTo:      &dialog,
		Title:         "Error!",
		DefaultButton: &okPB,
		MinSize:       declarative.Size{300, 100},
		Layout:        declarative.VBox{},
		Children: []declarative.Widget{

			declarative.Label{
				Text: errorMessage,
			},
			declarative.Composite{
				Layout: declarative.HBox{},
				Children: []declarative.Widget{
					declarative.PushButton{
						AssignTo: &okPB,
						Text:     "OK",

						OnClicked: func() {
							dialog.Accept()
						},
					},
				},
			},
		},
	}.Run(nil)
	if err != nil {
		fmt.Println(err)
	}
}

// askElevationDialog asks the user if he wants to elevates his rights
func askElevationDialog() {
	//var notifyTextEdit *walk.TextEdit
	var dialog *walk.Dialog
	var acceptPB, cancelPB *walk.PushButton
	_, err := declarative.Dialog{
		AssignTo:      &dialog,
		Title:         "Do you want to use admin privileges?",
		DefaultButton: &acceptPB,
		CancelButton:  &cancelPB,
		MinSize:       declarative.Size{300, 100},
		Layout:        declarative.VBox{},
		Children: []declarative.Widget{

			declarative.Label{
				Text: "You are currently running hardentools as normal user.",
				//TextColor: walk.RGB(255, 0, 0),
				//MinSize: declarative.Size{500, 50},
			},
			declarative.Label{
				Text:      "You won't be able to harden all available settings!",
				TextColor: walk.RGB(255, 0, 0),
				//MinSize:   declarative.Size{500, 50},
			},
			declarative.Label{
				Text: "If you have admin rights available, please press \"Yes\", otherwise press \"No\".",
				//TextColor: walk.RGB(255, 0, 0),
				//MinSize: declarative.Size{500, 50},
			},
			declarative.Composite{
				Layout: declarative.HBox{},
				Children: []declarative.Widget{
					declarative.PushButton{
						AssignTo: &acceptPB,
						Text:     "Yes",

						OnClicked: func() {
							dialog.Accept()
							restartWithElevatedPrivileges()
						},
					},
					declarative.PushButton{
						AssignTo:  &cancelPB,
						Text:      "No",
						OnClicked: func() { dialog.Cancel() },
					},
				},
			},
		},
	}.Run(nil)
	if err != nil {
		fmt.Println(err)
	}
}

// restartWithElevatedPrivileges tries to restart hardentools.exe with admin privileges
func restartWithElevatedPrivileges() {
	// find out our program (exe) name
	progName := os.Args[0]

	// start us again, this time with elevated privileges
	if C.ExecuteWithRunas(C.CString(progName)) == 1 {
		// exit this instance (the unprivileged one)
		os.Exit(0)
	} else {
		// something went wrong
		showErrorDialog("Error while trying to gain elevated privileges. Exiting.")
	}

	// exit this instance (the unprivileged one)
	os.Exit(0)
}

// main method for hardentools
func main() {
	// check if hardentools has been started with elevated rights. If not
	// ask user if he wants to elevate
	if C.IsElevated() == 0 {
		askElevationDialog()
	}

	// show splash screen
	splashChannel := make(chan bool, 1)
	showSplash(splashChannel)

	openMainWindow(splashChannel)
}
