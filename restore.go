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

// TODO: Add error handling for all methods

// save original registry key
func save_original_registry_DWORD(key registry.Key, key_name string, value_name string) {
	hardentools_key, _, _ := registry.CreateKey(registry.CURRENT_USER, harden_key_path, registry.ALL_ACCESS)

	original_value, _, err := key.GetIntegerValue(value_name)
	if err == nil {
		// save state
		hardentools_key.SetDWordValue("SavedState_"+key_name+"_"+value_name, uint32(original_value))
	}
	hardentools_key.Close()
}

// restore registry key from saved state
func retrieve_original_registry_DWORD(key_name string, value_name string) (value uint32, err error) {
	hardentools_key, _, _ := registry.CreateKey(registry.CURRENT_USER, harden_key_path, registry.ALL_ACCESS)

	// retrieve saved state
	value64, _, err := hardentools_key.GetIntegerValue("SavedState_" + key_name + "_" + value_name)
	hardentools_key.Close()
	if err == nil {
		return uint32(value64), nil
	}
	return 0, err
}

// Helper method for restoring original state
func restore_key(key registry.Key, key_name string, value_name string) {
	value, err := retrieve_original_registry_DWORD(key_name, value_name)
	if err == nil {
		key.SetDWordValue(value_name, value)
	} else {
		key.DeleteValue(value_name)
	}
}
