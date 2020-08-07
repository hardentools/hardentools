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

// HardenInterface is the general interface which should be used for every
// harden subject.
type HardenInterface interface {
	IsHardened() bool      // Returns true if harden subject is already completely hardened.
	Harden(bool) error     // Hardens the harden subject if parameter is true, restores it if parameter is false.
	Name() string          // Returns short name.
	LongName() string      // Returns long name.
	Description() string   // Returns description.
	HardenByDefault() bool // Returns if this harden subject should be hardened by default or only optional.
}

// MultiHardenInterfaces is a type for an array of HardenInterfaces.
type MultiHardenInterfaces struct {
	hardenInterfaces []HardenInterface
	shortName        string
	longName         string
	description      string
	hardenByDefault  bool
}

// Harden hardens (if harden == true) or restores (if harden == false)
// MultiHardenInterfaces.
func (mhInterfaces *MultiHardenInterfaces) Harden(harden bool) error {
	for _, mhInterface := range mhInterfaces.hardenInterfaces {
		err := mhInterface.Harden(harden)
		if err != nil {
			return err
		}
	}
	return nil
}

// IsHardened verifies if all MultiHardenInterfaces members are hardened.
func (mhInterfaces *MultiHardenInterfaces) IsHardened() bool {
	var hardened = true

	for _, mhInterface := range mhInterfaces.hardenInterfaces {
		if !mhInterface.IsHardened() {
			hardened = false
		}
	}

	return hardened
}

// Name returns the (short) name of the harden item.
func (mhInterfaces *MultiHardenInterfaces) Name() string {
	return mhInterfaces.shortName
}

// LongName returns the long name of the harden item.
func (mhInterfaces *MultiHardenInterfaces) LongName() string {
	return mhInterfaces.longName
}

// Description of the harden item.
func (mhInterfaces *MultiHardenInterfaces) Description() string {
	return mhInterfaces.description
}

// HardenByDefault returns if subject should be hardened by default.
func (mhInterfaces *MultiHardenInterfaces) HardenByDefault() bool {
	return mhInterfaces.hardenByDefault
}
