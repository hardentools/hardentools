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
	"errors"
	"fmt"
	"log"
	"strconv"

	"golang.org/x/sys/windows/registry"
)

// data type for a single registry DWORD value that suffices for hardening
// a distinct setting or as part of an RegistryMultiValue
type RegistrySingleValueDWORD struct {
	RootKey       registry.Key
	Path          string
	ValueName     string
	HardenedValue uint32
	shortName     string
	longName      string
	description   string
}

// data type for multiple SingleValueDWORDs
// use if a single hardening needs multiple RegistrySingleValueDWORD to be modified
type RegistryMultiValue struct {
	ArraySingleDWORD []*RegistrySingleValueDWORD
	shortName        string
	longName         string
	description      string
}

// harden function for RegistrySingleValueDWORD struct
func (regValue *RegistrySingleValueDWORD) Harden(harden bool) error {
	/*key, _, err := registry.CreateKey(regValue.RootKey, regValue.Path, registry.WRITE)
	if err != nil {
		return errors.New(fmt.Sprintf("Couldn't create / open registry key for write access: %s \\ %s", regValue.RootKey, regValue.Path))
	}
	defer key.Close()*/

	if harden == false {
		// Restore.
		return restoreKey(regValue.RootKey, regValue.Path, regValue.ValueName)
	} else {
		return HardenDwordValue(regValue.RootKey, regValue.Path, regValue.ValueName, regValue.HardenedValue)
		/*// Save current state.
		err = saveOriginalRegistryDWORD(regValue.RootKey, regValue.Path, regValue.ValueName)
		if err != nil {
			return err
		}
		// Harden.
		err = key.SetDWordValue(regValue.ValueName, regValue.HardenedValue)
		if err != nil {
			return errors.New(fmt.Sprintf("Couldn't set registry value: %s \\ %s \\ %s", regValue.RootKey, regValue.Path, regValue.ValueName))
		}*/
	}

	return nil
}

// verify if harden object of type RegistrySingleValueDWORD is already hardened
func (regValue *RegistrySingleValueDWORD) IsHardened() bool {
	key, err := registry.OpenKey(regValue.RootKey, regValue.Path, registry.READ)

	if err == nil {
		currentValue, _, err := key.GetIntegerValue(regValue.ValueName)
		if err == nil {
			if uint32(currentValue) == regValue.HardenedValue {
				return true
			}
		}
	}
	return false
}

func (regValue *RegistrySingleValueDWORD) Name() string {
	return regValue.shortName
}

func (regValue *RegistrySingleValueDWORD) LongName() string {
	return regValue.longName
}

func (regValue *RegistrySingleValueDWORD) Description() string {
	return regValue.description
}

// harden function for RegistryMultiValue struct
func (regMultiValue RegistryMultiValue) Harden(harden bool) error {
	for _, singleDWORD := range regMultiValue.ArraySingleDWORD {
		err := singleDWORD.Harden(harden)
		if err != nil {
			log.Fatal("Could not harden " + singleDWORD.Name() + " due to error: " + err.Error())
			return err
		}
	}
	return nil
}

// verify if harden object of type RegistryMultiValue is already hardened
func (regMultiValue *RegistryMultiValue) IsHardened() (isHardened bool) {
	var hardened = true

	for _, singleDWORD := range regMultiValue.ArraySingleDWORD {
		if !singleDWORD.IsHardened() {
			hardened = false
		}
	}

	return hardened
}

func (regMultiValue *RegistryMultiValue) Name() string {
	return regMultiValue.shortName
}

func (regMultiValue *RegistryMultiValue) LongName() string {
	return regMultiValue.longName
}

func (regMultiValue *RegistryMultiValue) Description() string {
	return regMultiValue.description
}

////
// save and restore methods

// helper method for saving original registry key.
func saveOriginalRegistryDWORD(rootKey registry.Key, keyName string, valueName string) error {
	// open hardentools root key
	hardentoolsKey, _, err := registry.CreateKey(registry.CURRENT_USER, hardentoolsKeyPath, registry.ALL_ACCESS)
	if err != nil {
		return err
	}
	defer hardentoolsKey.Close()

	// get value of registry key to save
	keyToSave, err := registry.OpenKey(rootKey, keyName, registry.READ)
	if err != nil {
		log.Println("Could not open registry key to save due to error: " + err.Error())
		return err
	}
	defer keyToSave.Close()

	// now finally get value to save
	originalValue, _, err := keyToSave.GetIntegerValue(valueName)
	if err != nil {
		log.Println("Could not retrieve value of registry key to save (" + keyName + ", " + valueName + ") due to error: " + err.Error())
		return nil // nothing to save (no error, normal behaviour if registry key was not set)
	} else {
		// get name of root ke (e.g. CURRENT_USER)
		rootKeyName, err := getRootKeyName(rootKey)
		if err != nil {
			return err
		}

		// save value
		log.Println("Saving value for: " + "SavedState_" + rootKeyName + "\\" + keyName + "_" + valueName)
		err = hardentoolsKey.SetDWordValue("SavedState_"+rootKeyName+"\\"+keyName+"_"+valueName, uint32(originalValue))
		if err != nil {
			log.Fatal("Could not save state")
		}
		return err
	}
}

// helper method for restoring registry key from saved state.
func retrieveOriginalRegistryDWORD(rootKey registry.Key, keyName string, valueName string) (value uint32, err error) {
	// open hardentools root key
	hardentoolsKey, _, err := registry.CreateKey(registry.CURRENT_USER, hardentoolsKeyPath, registry.ALL_ACCESS)
	if err != nil {
		return 0, err
	}
	defer hardentoolsKey.Close()

	// get rootKeyName
	rootKeyName, err := getRootKeyName(rootKey)
	if err != nil {
		log.Println("Could not get rootKeyName")
		return 0, nil
	}

	// get saved state
	value64, _, err := hardentoolsKey.GetIntegerValue("SavedState_" + rootKeyName + "\\" + keyName + "_" + valueName)
	if err != nil {
		//log.Println("Could not get saved state for SavedState_" + rootKeyName + "\\" + keyName + "_" + valueName)
		return 0, err
	} else {
		return uint32(value64), nil
	}
}

// Helper method for restoring original state of a DWORD registry key.
func restoreKey(rootKey registry.Key, keyName string, valueName string) (err error) {
	// open key to be restored
	key, err := registry.OpenKey(rootKey, keyName, registry.ALL_ACCESS)
	if err != nil {
		log.Println("Could not open registry key " + keyName + " due to error: " + err.Error())
		return err
	}
	defer key.Close()

	// get original state value
	value, err := retrieveOriginalRegistryDWORD(rootKey, keyName, valueName)
	if err == nil {
		log.Println("Restoring registry value " + keyName + "\\" + valueName + " to saved state " + strconv.FormatUint(uint64(value), 16))
		err = key.SetDWordValue(valueName, value)
	} else {
		log.Println("Could not get saved value, therefore deleting the registry value " + valueName)
		err = key.DeleteValue(valueName)
	}
	return err
}

// get root key name (LOCAL_MACHINE vs. LOCAL_USER)
func getRootKeyName(rootKey registry.Key) (rootKeyName string, err error) {
	// this is kind of a hack, since registry.Key doesn't allow to get the
	// name of the key itself

	switch rootKey {
	case registry.CLASSES_ROOT:
		rootKeyName = "CLASSES_ROOT"
	case registry.CURRENT_USER:
		rootKeyName = "CURRENT_USER"
	case registry.LOCAL_MACHINE:
		rootKeyName = "LOCAL_MACHINE"
	case registry.USERS:
		rootKeyName = "USERS"
	case registry.CURRENT_CONFIG:
		rootKeyName = "CURRENT_CONFIG"
	case registry.PERFORMANCE_DATA:
		rootKeyName = "PERFORMANCE_DATA"
	default:
		// invalid rootKey?
		log.Fatal("Invalid rootKey provided to save registry function")
		err = errors.New("Invalid rootKey provided to save registry function")
	}

	return
}

// harden Dword value including saving the original state
func HardenDwordValue(rootKey registry.Key, path string, valueName string, hardenedValue uint32) error {
	rootKeyName, _ := getRootKeyName(rootKey)
	key, _, err := registry.CreateKey(rootKey, path, registry.WRITE)
	if err != nil {
		return errors.New(fmt.Sprintf("Couldn't create / open registry key for write access: %s\\%s", rootKeyName, path))
	}
	defer key.Close()

	// Save current state.
	err = saveOriginalRegistryDWORD(rootKey, path, valueName)
	if err != nil {
		return err
	}
	// Harden.
	err = key.SetDWordValue(valueName, hardenedValue)
	if err != nil {
		return errors.New(fmt.Sprintf("Couldn't set registry value: %s \\ %s \\ %s", rootKeyName, path, valueName))
	}

	return nil
}
