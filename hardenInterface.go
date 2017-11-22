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

// Generale interface which should be used for every harden subject
type HardenInterface interface {
	isHardened() bool  // returns true if harden subject is already completely hardened
	harden(bool) error // hardens the harden subject if parameter is true, restores it if parameter is false
	name() string      // returns short name
}

// type for array of HardenInterfaces
type MultiHardenInterfaces struct {
	HardenInterfaces []HardenInterface
	shortName        string
}

func (mhInterfaces *MultiHardenInterfaces) harden(harden bool) error {
	for _, mhInterface := range mhInterfaces.HardenInterfaces {
		err := mhInterface.harden(harden)
		if err != nil {
			return err
		}
	}
	return nil
}

func (mhInterfaces *MultiHardenInterfaces) isHardened() bool {
	var hardened = true

	for _, mhInterface := range mhInterfaces.HardenInterfaces {
		if !mhInterface.isHardened() {
			hardened = false
		}
	}

	return hardened
}

func (mhInterfaces *MultiHardenInterfaces) name() string {
	return mhInterfaces.shortName
}

// error handling
type HardenError struct {
	err string
}

func (e HardenError) Error() string {
	return e.err
}
