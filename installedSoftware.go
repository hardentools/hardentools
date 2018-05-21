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
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"

	"golang.org/x/sys/windows/registry"
)

// struct for HardenInterface implementation
type InstalledSoftware struct {
	shortName   string
	longName    string
	description string
}

// var for HardenInterface implementation used by main.go
var InstSoftware = &InstalledSoftware{
	shortName:   "ShowInstalledSoftware",
	longName:    "Show Installed Software",
	description: "Shows installed software",
}

// struct for the registry keys needed to read out installed software
type registryKeys struct {
	rootKey registry.Key
	path    string
}

// this struct is used for filling in software attributes for most current stable
// version of software available for download (attributes must match the
// corresponding JSON elements for Vergrabber.json)
type softwareReleaseStatus struct {
	Name         string // filled in manually from Vergrabber.json
	MajorRelease string // filled in manually from Vergrabber.json
	Stable       bool   // automatically unmarshalled from Vergrabber.json
	Version      string // automatically unmarshalled from Vergrabber.json
	Latest       bool   // automatically unmarshalled from Vergrabber.json
	Ends         string // automatically unmarshalled from Vergrabber.json
	Edition      string // automatically unmarshalled from Vergrabber.json
	Product      string // automatically unmarshalled from Vergrabber.json
	Released     string // automatically unmarshalled from Vergrabber.json
}

// this struct is used for filling in software attributes for software
// that is actually installed on the system
type installedSoftwareComponent struct {
	displayName    string
	displayVersion string
	publisher      string
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
	// fetch Windows version
	maj, min, cb, err := getWindowsVersion()
	if err == nil {
		Info.Printf("Windows Version: %d.%d.%s", maj, min, cb)
	} else {
		Info.Printf("Error getting Windows Version: %s", err)
	}

	// fetch installed software
	foundSoftware, err := getInstalledSoftware()
	if err == nil {
		for key, soft := range foundSoftware {
			Info.Printf("%s: %s %s (%s)", key, soft.displayName, soft.displayVersion, soft.publisher)
		}
	} else {
		return false
	}

	// fetch software current release information from Vergrabber
	softwareReleaseStatii := getSoftwareVersionsFromVergrabber()
	Trace.Printf("Software Releases from Vergrabber: %s", softwareReleaseStatii)
	//fmt.Println("Software Releases from Vergrabber:\n", softwareReleaseStatii)

	verifyInstalledSoftwareVersions(foundSoftware, softwareReleaseStatii)

	// TODO: get patch level
	/* TODO (from https://github.com/Jean13/CVE_Compare/tree/master/go):

	# Get list of installed KB's

	wmic qfe get HotFixID","InstalledOn

	$get_kb = wmic qfe get HotFixID

	$kb_file = "kb_list.txt"

	$get_kb >> $kb_file
	*/

	// TODO: verify patch level against Vergrabber

	return false
}

// HardenInterface method
func (software InstalledSoftware) Name() string {
	return software.shortName
}

// HardenInterface method
func (software InstalledSoftware) LongName() string {
	return software.longName
}

// HardenInterface method
func (software InstalledSoftware) Description() string {
	return software.description
}

// tries to find matches between installed software components and
// software release statii.
// works at least for Firefox, Chrome and Teamviewer (in current versions)
// TODO: Does not do anything right now beneath logging
func verifyInstalledSoftwareVersions(installedSoftware map[string]installedSoftwareComponent, softwareReleaseStatii map[string]softwareReleaseStatus) {
	for _, installedComponent := range installedSoftware {
		searchName := strings.Split(installedComponent.displayName, ".")[0]
		if searchName != "" {
			for statKey, statValue := range softwareReleaseStatii {
				searchStatKey := strings.Split(statKey, ".")[0]

				//fmt.Println("checking if", searchName, " contains ", searchStatKey)
				if strings.Contains(searchName, searchStatKey) || strings.Contains(searchStatKey, searchName) {
					//fmt.Printf("Possible match found: Installed software \"%s\" (%s) might match \"%s\" (%s)\n", installedComponent.displayName, installedComponent.displayVersion, statKey, statValue.Version)
					Info.Printf("Possible match found: Installed software \"%s\" (%s) might match \"%s\" (%s)", installedComponent.displayName, installedComponent.displayVersion, statKey, statValue.Version)
				}
			}
		}
	}

}

// gets Windows version numbers (Major, Minor and CurrentBuild)
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

// reads installed software from Microsoft Windows official registry keys
func getInstalledSoftware() (map[string]installedSoftwareComponent, error) {
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
			return nil, errors.New(fmt.Sprintf("Could not open registry key %s due to error %s", regKeysUninstall[i].path, err.Error()))
		}
		defer key.Close()

		keyInfo, _ := key.Stat()
		subKeys, err := key.ReadSubKeyNames(int(keyInfo.SubKeyCount))
		if err != nil {
			Info.Printf("Could not read sub keys of registry key %s due to error %s", regKeysUninstall[i].path, err.Error())
			return nil, errors.New(fmt.Sprintf("Could not read sub keys of registry key %s due to error %s", regKeysUninstall[i].path, err.Error()))
		}

		for j := 0; j < len(subKeys); j++ {
			subKey, err := registry.OpenKey(regKeysUninstall[i].rootKey, regKeysUninstall[i].path+"\\"+subKeys[j], registry.READ)
			if err != nil {
				Info.Printf("Could not open registry key %s due to error %s", subKeys[j], err.Error())
				return nil, errors.New(fmt.Sprintf("Could not open registry key %s due to error %s", subKeys[j], err.Error()))
			}
			defer subKey.Close()

			displayName, _, _ := subKey.GetStringValue("DisplayName")
			displayVersion, _, _ := subKey.GetStringValue("DisplayVersion")
			publisher, _, _ := subKey.GetStringValue("Publisher")
			Trace.Printf("getInstalledSoftware: %s: %s %s (%s)", subKeys[j], displayName, displayVersion, publisher)

			newSoftwareFound := installedSoftwareComponent{displayName, displayVersion, publisher}
			foundSoftware[subKeys[j]] = newSoftwareFound
		}
	}

	return foundSoftware, nil
}

// fetches current versions of common software from
// http://vergrabber.kingu.pl/vergrabber.json
func getSoftwareVersionsFromVergrabber() map[string]softwareReleaseStatus {
	softwareReleaseStatii := map[string]softwareReleaseStatus{}

	// get JSON
	url := "http://vergrabber.kingu.pl/vergrabber.json"
	resp, err := http.Get(url)
	// handle the error if there is one
	if err != nil {
		panic(err)
	}
	// do this now so it won't be forgotten
	defer resp.Body.Close()

	// reads json as a slice of bytes
	jsonFromVergrabber, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}

	//Info.Printf("%s\n", jsonFromVergrabber)

	// parse JSON
	var f map[string]map[string]map[string]softwareReleaseStatus
	err = json.Unmarshal(jsonFromVergrabber, &f)

	for _, valueSoftwareType := range f {
		//fmt.Println("Typ:", softwareType)
		for softwareName, softwareDetails := range valueSoftwareType {
			//fmt.Println("Name:", softwareName)
			for softwareVersion, softwareVersionDetails := range softwareDetails {
				softwareVersionDetails.Name = softwareName
				softwareVersionDetails.MajorRelease = softwareVersion

				//fmt.Println("Version:", softwareVersion)
				//fmt.Println("Details:", softwareVersionDetails)

				softwareReleaseStatii[softwareName+" "+softwareVersion] = softwareVersionDetails
			}
		}
	}

	return softwareReleaseStatii
}
