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
	"golang.org/x/sys/windows/registry"
)

// TODO: Add error handling for all methods.

// Save original registry key.
func saveOriginalRegistryDWORD(key registry.Key, keyName string, valueName string) {
	hardentoolsKey, _, _ := registry.CreateKey(registry.CURRENT_USER, harden_key_path, registry.ALL_ACCESS)

	originalValue, _, err := key.GetIntegerValue(valueName)
	if err == nil {
		hardentoolsKey.SetDWordValue("SavedState_" + keyName + "_" + valueName, uint32(originalValue))
	}
	hardentoolsKey.Close()
}

// Restore registry key from saved state.
func retrieveOriginalRegistryDWORD(keyName string, valueName string) (value uint32, err error) {
	hardentoolsKey, _, _ := registry.CreateKey(registry.CURRENT_USER, harden_key_path, registry.ALL_ACCESS)

	value64, _, err := hardentoolsKey.GetIntegerValue("SavedState_" + keyName + "_" + valueName)
	hardentoolsKey.Close()
	if err == nil {
		return uint32(value64), nil
	}
	return 0, err
}

// Helper method for restoring original state.
func restoreKey(key registry.Key, keyName string, valueName string) {
	value, err := retrieveOriginalRegistryDWORD(keyName, valueName)
	if err == nil {
		key.SetDWordValue(valueName, value)
	} else {
		key.DeleteValue(valueName)
	}
}
