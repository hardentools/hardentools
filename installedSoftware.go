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
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package main

import (
	"errors"

	"golang.org/x/sys/windows/registry"
)

type InstalledSoftware struct {
	shortName   string
	longName    string
	description string
}

type registryKeys struct {
	rootKey registry.Key
	path    string
}

type installedSoftwareComponent struct {
	displayName    string
	displayVersion string
	publisher      string
}

var InstSoftware = &InstalledSoftware{
	shortName:   "ShowInstalledSoftware",
	longName:    "Show Installed Software",
	description: "Shows installed software",
}

func (software InstalledSoftware) Harden(harden bool) error {
	if harden == false {
		// Restore.

	} else {
		// Harden.

	}

	return nil
}

func (software InstalledSoftware) IsHardened() bool {
	// Windows version
	maj, min, cb, err := getWindowsVersion()
	if err == nil {
		Info.Printf("Windows Version: %d.%d.%s", maj, min, cb)
	} else {
		Info.Printf("Error getting Windows Version: %s", err)
	}

	// Software from Uninstall registry keys
	regKeysUninstall := []registryKeys{
		{registry.LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall"},
		{registry.LOCAL_MACHINE, "SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall"},
		{registry.CURRENT_USER, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall"},
	}

	foundSoftware := make(map[string]installedSoftwareComponent)

	for i := 0; i < len(regKeysUninstall); i++ {
		//Info.Printf("%d:%s", regKeysUninstall[i].rootKey, regKeysUninstall[i].path)
		key, err := registry.OpenKey(regKeysUninstall[i].rootKey, regKeysUninstall[i].path, registry.READ)
		if err != nil {
			Info.Printf("Could not open registry key %s due to error %s", regKeysUninstall[i].path, err.Error())
			return false
		}
		defer key.Close()

		keyInfo, _ := key.Stat()
		subKeys, err := key.ReadSubKeyNames(int(keyInfo.SubKeyCount))
		if err != nil {
			Info.Printf("Could not read sub keys of registry key %s due to error %s", regKeysUninstall[i].path, err.Error())
			return false
		}

		for j := 0; j < len(subKeys); j++ {
			subKey, err := registry.OpenKey(regKeysUninstall[i].rootKey, regKeysUninstall[i].path+"\\"+subKeys[j], registry.READ)
			if err != nil {
				Info.Printf("Could not open registry key %s due to error %s", subKeys[j], err.Error())
				return false
			}
			defer subKey.Close()

			displayName, _, _ := subKey.GetStringValue("DisplayName")
			displayVersion, _, _ := subKey.GetStringValue("DisplayVersion")
			publisher, _, _ := subKey.GetStringValue("Publisher")
			//Info.Printf("%s: %s %s (%s)", subKeys[j], displayName, displayVersion, publisher)
			newSoftwareFound := installedSoftwareComponent{displayName, displayVersion, publisher}
			foundSoftware[subKeys[j]] = newSoftwareFound
		}
	}

	for key, soft := range foundSoftware {
		Info.Printf("%s: %s %s (%s)", key, soft.displayName, soft.displayVersion, soft.publisher)
	}

	// get patch level
	/* TODO (from https://github.com/Jean13/CVE_Compare/tree/master/go):

	# Get list of installed KB's

	wmic qfe get HotFixID","InstalledOn

	$get_kb = wmic qfe get HotFixID

	$kb_file = "kb_list.txt"

	$get_kb >> $kb_file
	*/

	return false
}

func (software InstalledSoftware) Name() string {
	return software.shortName
}

func (software InstalledSoftware) LongName() string {
	return software.longName
}

func (software InstalledSoftware) Description() string {
	return software.description
}

// gets Windows version numbers
func getWindowsVersion() (CurrentMajorVersionNumber, CurrentMinorVersionNumber uint64, CurrentBuild string, err error) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", registry.QUERY_VALUE)
	if err != nil {
		return 0, 0, "", errors.New("Could not get version information from registry")
	}
	defer k.Close()

	maj, _, err := k.GetIntegerValue("CurrentMajorVersionNumber")
	if err != nil {
		return 0, 0, "", errors.New("Could not get version information from registry")
	}

	min, _, err := k.GetIntegerValue("CurrentMinorVersionNumber")
	if err != nil {
		return maj, 0, "", errors.New("Could not get version information from registry")
	}

	cb, _, err := k.GetStringValue("CurrentBuild")
	if err != nil {
		return maj, min, "", errors.New("Could not get version information from registry")
	}

	return maj, min, cb, nil
}
