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

import (
	"errors"
	"fmt"
	"strings"

	"golang.org/x/sys/windows/registry"
)

// RegistrySingleValueDWORD is a data type for a single registry DWORD value
// that suffices for hardening a distinct setting or as part of a
// RegistryMultiValue.
type RegistrySingleValueDWORD struct {
	RootKey         registry.Key
	Path            string
	ValueName       string
	HardenedValue   uint32
	shortName       string
	longName        string
	description     string
	hardenByDefault bool
}

// RegistryMultiValue is a data type for multiple SingleValueDWORDs
// use if a single hardening needs multiple RegistrySingleValueDWORD to be
// modified.
type RegistryMultiValue struct {
	ArraySingleDWORD []*RegistrySingleValueDWORD
	shortName        string
	longName         string
	description      string
	hardenByDefault  bool
}

// Harden function for RegistrySingleValueDWORD struct.
func (regValue *RegistrySingleValueDWORD) Harden(harden bool) error {
	if harden == false {
		// Restore.
		return restoreKey(regValue.RootKey, regValue.Path, regValue.ValueName)
	}

	// else: Harden.
	return hardenKey(regValue.RootKey, regValue.Path, regValue.ValueName, regValue.HardenedValue)
}

// IsHardened verifies if harden object of type RegistrySingleValueDWORD
// is already hardened.
func (regValue *RegistrySingleValueDWORD) IsHardened() bool {
	key, err := registry.OpenKey(regValue.RootKey, regValue.Path, registry.READ)

	if err == nil {
		currentValue, _, err := key.GetIntegerValue(regValue.ValueName)
		if err == nil {
			if uint32(currentValue) == regValue.HardenedValue {
				Trace.Printf("IsHardened?: (OK) %s\\%s = %d",
					regValue.Path, regValue.ValueName, currentValue)
				return true
			}
			Trace.Printf("IsHardened?: (not) %s\\%s = %d (hardened value = %d)",
				regValue.Path, regValue.ValueName, currentValue,
				regValue.HardenedValue)
		}
	}
	Trace.Printf("IsHardened?: (not) %s\\%s (not found)",
		regValue.Path, regValue.ValueName)
	return false
}

// Name returns the (short) name of the harden item.
func (regValue *RegistrySingleValueDWORD) Name() string {
	return regValue.shortName
}

// LongName returns the long name of the harden item.
func (regValue *RegistrySingleValueDWORD) LongName() string {
	return regValue.longName
}

// Description of the harden item.
func (regValue *RegistrySingleValueDWORD) Description() string {
	return regValue.description
}

// HardenByDefault returns if subject should be hardened by default.
func (regValue *RegistrySingleValueDWORD) HardenByDefault() bool {
	return regValue.hardenByDefault
}

// Harden function for RegistryMultiValue struct.
func (regMultiValue RegistryMultiValue) Harden(harden bool) error {
	for _, singleDWORD := range regMultiValue.ArraySingleDWORD {
		err := singleDWORD.Harden(harden)
		if err != nil {
			Info.Println("Could not harden " + singleDWORD.Name() +
				" due to error: " + err.Error())
			return err
		}
	}
	return nil
}

// IsHardened verifies if harden object of type RegistryMultiValue is already
// hardened.
func (regMultiValue *RegistryMultiValue) IsHardened() (isHardened bool) {
	var hardened = true

	for _, singleDWORD := range regMultiValue.ArraySingleDWORD {
		if !singleDWORD.IsHardened() {
			hardened = false
		}
	}

	return hardened
}

// Name returns the (short) name of the harden item.
func (regMultiValue *RegistryMultiValue) Name() string {
	return regMultiValue.shortName
}

// LongName returns the long name of the harden item.
func (regMultiValue *RegistryMultiValue) LongName() string {
	return regMultiValue.longName
}

// Description of the harden item.
func (regMultiValue *RegistryMultiValue) Description() string {
	return regMultiValue.description
}

// HardenByDefault returns if subject should be hardened by default.
func (regMultiValue *RegistryMultiValue) HardenByDefault() bool {
	return regMultiValue.hardenByDefault
}

// Helper methods.
// Get root key name (LOCAL_MACHINE vs. LOCAL_USER).
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
		Info.Println("Invalid rootKey provided to save registry function")
		err = errors.New("Invalid rootKey provided to save registry function")
	}
	return
}

// Get root key from name (LOCAL_MACHINE vs. LOCAL_USER).
func getRootKeyFromName(rootKeyName string) (rootKey registry.Key, err error) {
	switch rootKeyName {
	case "CLASSES_ROOT":
		rootKey = registry.CLASSES_ROOT
	case "CURRENT_USER":
		rootKey = registry.CURRENT_USER
	case "LOCAL_MACHINE":
		rootKey = registry.LOCAL_MACHINE
	case "USERS":
		rootKey = registry.USERS
	case "CURRENT_CONFIG":
		rootKey = registry.CURRENT_CONFIG
	case "PERFORMANCE_DATA":
		rootKey = registry.PERFORMANCE_DATA
	default:
		// Invalid rootKeyName?
		Info.Println("Invalid rootKeyName provided to restore registry function")
		err = errors.New("Invalid rootKeyName provided to restore registry function")
		return registry.CURRENT_USER, err
	}
	return rootKey, nil
}

// Harden Dword value including saving the original state.
func hardenKey(rootKey registry.Key, path string, valueName string, hardenedValue uint32) error {
	rootKeyName, _ := getRootKeyName(rootKey)
	key, _, err := registry.CreateKey(rootKey, path, registry.WRITE)
	if err != nil {
		return fmt.Errorf("Couldn't create / open registry key for write access: %s\\%s",
			rootKeyName, path)
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
		return fmt.Errorf("Couldn't set registry value: %s \\ %s \\ %s",
			rootKeyName, path, valueName)
	}

	return nil
}

// Helper method for saving original registry key.
func saveOriginalRegistryDWORD(rootKey registry.Key, keyName string, valueName string) error {
	saveNonExisting := false

	// Open hardentools root key.
	hardentoolsKey, _, err := registry.CreateKey(registry.CURRENT_USER,
		hardentoolsKeyPath, registry.ALL_ACCESS)
	if err != nil {
		return err
	}
	defer hardentoolsKey.Close()

	// Get name of root key (e.g. CURRENT_USER).
	rootKeyName, err := getRootKeyName(rootKey)
	if err != nil {
		return err
	}

	// Open registry key.
	keyToSave, err := registry.OpenKey(rootKey, keyName, registry.READ)
	if err != nil {
		//Trace.Println("Could not open registry key to save due to error: " + err.Error())
		saveNonExisting = true
	} else {
		defer keyToSave.Close()

		// Now finally get value to save.
		originalValue, _, err := keyToSave.GetIntegerValue(valueName)
		if err != nil {
			//Trace.Println("Could not retrieve registry value to save (" + keyName + ", " + valueName + ") due to error: " + err.Error())
			saveNonExisting = true
		} else {
			// save value
			Trace.Println("Saving value for: " + "SavedStateNew_" + rootKeyName + "\\" + keyName + "_" + valueName)
			err = hardentoolsKey.SetDWordValue("SavedStateNew_"+rootKeyName+"\\"+keyName+"____"+valueName, uint32(originalValue))
			if err != nil {
				Info.Println("Could not save state due to error: " + err.Error())
			}
		}
	}

	if saveNonExisting {
		// Save as not existing before hardening.
		Trace.Println("Saving " + rootKeyName + "\\" + keyName + "_" + valueName + " as not existing before hardening")
		err = hardentoolsKey.SetDWordValue("SavedStateNotExisting_"+rootKeyName+"\\"+keyName+"____"+valueName, 0)
		if err != nil {
			Info.Println("Could not save state due to error: " + err.Error())
			return err
		}
	}

	return nil
}

// Helper method for restoring original state of a DWORD registry key.
// TODO: remove this method and replace with restoreSavedRegistryKeys
//       in future version (see inline comment)
func restoreKey(rootKey registry.Key, keyName string, valueName string) (err error) {
	// Open key to be restored.
	key, err := registry.OpenKey(rootKey, keyName, registry.ALL_ACCESS)
	if err != nil {
		Info.Println("Could not open registry key " + keyName + " due to error: " + err.Error())
		return err
	}
	defer key.Close()

	// Get original state value.
	value, err := retrieveOriginalRegistryDWORD(rootKey, keyName, valueName)
	if err == nil {
		Trace.Printf("Restore: Restoring registry value %s\\%s = %d", keyName, valueName, value)
		err = key.SetDWordValue(valueName, value)
	} else {
		// TODO: here it is assumed that registry keys which were not safed did not
		// exist during hardening. This assumption is from old versions of
		// hardentools and still included to being able to restore old hardens
		// with the current version of hardentools. Since this would also lead
		// to settings being deleted when introducing new functionality in
		// hardentools, this will be removed in upcoming versions
		Trace.Println("Restore: Could not get saved reg. value, deleting " + keyName + "\\" + valueName)
		err = key.DeleteValue(valueName)
	}
	return err
}

// Helper method for restoring registry key from saved state.
func retrieveOriginalRegistryDWORD(rootKey registry.Key, keyName string, valueName string) (value uint32, err error) {
	// Open hardentools root key
	hardentoolsKey, _, err := registry.CreateKey(registry.CURRENT_USER, hardentoolsKeyPath, registry.ALL_ACCESS)
	if err != nil {
		return 0, err
	}
	defer hardentoolsKey.Close()

	// Get rootKeyName.
	rootKeyName, err := getRootKeyName(rootKey)
	if err != nil {
		Info.Println("Could not get rootKeyName")
		return 0, err
	}

	// Get saved state
	value64, _, err := hardentoolsKey.GetIntegerValue("SavedState_" + rootKeyName + "\\" + keyName + "_" + valueName)
	if err != nil {
		return 0, err
	}

	return uint32(value64), nil
}

// restoreSavedRegistryKeys restores all saved registry keys from their saved
// registry state.
func restoreSavedRegistryKeys() error {
	// Open hardentools root key.
	hardentoolsKey, err := registry.OpenKey(registry.CURRENT_USER, hardentoolsKeyPath, registry.QUERY_VALUE)
	if err != nil {
		return err
	}
	defer hardentoolsKey.Close()

	params, err := hardentoolsKey.ReadValueNames(0)
	if err != nil {
		Info.Printf("Can't ReadSubKeyNames %s %#v", hardentoolsKeyPath, err)
		return err
	}

	settings := make(map[string]uint64)
	for _, param := range params {
		val, _, err := hardentoolsKey.GetIntegerValue(param)
		if err != nil {
			Info.Println(err)
			return err
		}
		settings[param] = val
	}
	//Trace.Printf("%#v\n", settings)

	for regKey, regValue := range settings {
		if strings.HasPrefix(regKey, "SavedState_") {
			// TODO: this section can be removed in future versions
			regKey = strings.TrimPrefix(regKey, "SavedState_")
			rootKeyName := strings.Split(regKey, "\\")[0]
			regKey = strings.TrimPrefix(regKey, rootKeyName)
			regKey = strings.TrimPrefix(regKey, "\\")
			valueName := regKey[strings.LastIndex(regKey, "_")+1:]
			regKey = strings.TrimSuffix(regKey, "_"+valueName)
			Trace.Printf("to be restored: %s\\%s\\%s = %d\n", rootKeyName,
				regKey, valueName, regValue)

			rootKey, err := getRootKeyFromName(rootKeyName)
			if err == nil {
				key, err := registry.OpenKey(rootKey, regKey, registry.ALL_ACCESS)
				if err != nil {
					Info.Println("Could not open registry key " + regKey + " due to error: " + err.Error())
				} else {
					defer key.Close()

					Info.Printf("restoreSavedRegistryKeys: Restoring registry value %s\\%s = %d",
						regKey, valueName, regValue)
					err = key.SetDWordValue(valueName, uint32(regValue))
					if err != nil {
						Info.Printf("Could not restore registry value %s\\%s = %d due to error: %s\n",
							regKey, valueName, regValue, err.Error())
					}
				}
			}
		} else if strings.HasPrefix(regKey, "SavedStateNew_") {
			regKey = strings.TrimPrefix(regKey, "SavedStateNew_")
			rootKeyName := strings.Split(regKey, "\\")[0]
			regKey = strings.TrimPrefix(regKey, rootKeyName)
			regKey = strings.TrimPrefix(regKey, "\\")
			valueName := regKey[strings.LastIndex(regKey, "____")+4:]
			regKey = strings.TrimSuffix(regKey, "____"+valueName)
			Trace.Printf("to be restored: %s\\%s\\%s = %d\n", rootKeyName, regKey, valueName, regValue)

			rootKey, err := getRootKeyFromName(rootKeyName)
			if err == nil {
				key, err := registry.OpenKey(rootKey, regKey, registry.ALL_ACCESS)
				if err != nil {
					Info.Println("Could not open registry key " + regKey + " due to error: " + err.Error())
				} else {
					defer key.Close()

					Trace.Printf("restoreSavedRegistryKeys: Restoring registry value %s\\%s = %d",
						regKey, valueName, regValue)
					err = key.SetDWordValue(valueName, uint32(regValue))
					if err != nil {
						Info.Printf("Could not restore registry value %s\\%s = %d due to error: %s\n",
							regKey, valueName, regValue, err.Error())
					}
				}
			}
		} else if strings.HasPrefix(regKey, "SavedStateNotExisting_") {
			regKey = strings.TrimPrefix(regKey, "SavedStateNotExisting_")
			rootKeyName := strings.Split(regKey, "\\")[0]
			regKey = strings.TrimPrefix(regKey, rootKeyName)
			regKey = strings.TrimPrefix(regKey, "\\")
			valueName := regKey[strings.LastIndex(regKey, "____")+4:]
			regKey = strings.TrimSuffix(regKey, "____"+valueName)
			Trace.Printf("to be restored (deleted): %s\\%s\\%s\n", rootKeyName, regKey, valueName)

			rootKey, err := getRootKeyFromName(rootKeyName)
			if err == nil {
				key, err := registry.OpenKey(rootKey, regKey, registry.ALL_ACCESS)
				if err != nil {
					Info.Println("Could not open registry key " + regKey + " due to error: " + err.Error())
				} else {
					defer key.Close()

					err = key.DeleteValue(valueName)
					if err != nil {
						// should be Info logger in the future, when registry
						// keys are not deleted by restoreKey() anymore
						Trace.Printf("Could not restore registry value (by deleting) %s\\%s due to error: %s\n",
							regKey, valueName, err.Error())
					}
				}
			}
		}
	}
	return err
}
