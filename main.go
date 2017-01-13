/*
    Hardentools
    Copyright (C) 2017  Claudio Guarnieri, Mariano Graziano

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

package main

import (
    "fmt"
    "flag"
    "golang.org/x/sys/windows/registry"
)

func mark_status(is_active bool) {
    key, _, err := registry.CreateKey(registry.CURRENT_USER, "SOFTWARE\\Security Without Borders\\", registry.WRITE)
    if err != nil {
        panic(err)
    }

    if is_active {
        key.SetDWordValue("Harden", 1)
    } else {
        key.SetDWordValue("Harden", 0)
    }
}

func main() {
    restore := flag.Bool("restore", false, "Restore original settings")
    flag.Parse()

    if *restore {
        fmt.Println("Restoring original settings...")

        trigger_wsh(true)
        trigger_ole(true)
        trigger_macro(true)
        trigger_pdf_js(true)
        trigger_pdf_objects(true)

        mark_status(false)
    } else {
        fmt.Println("Disabling dangerous features...")

        trigger_wsh(false)
        trigger_ole(false)
        trigger_macro(false)
        trigger_pdf_js(false)
        trigger_pdf_objects(false)

        mark_status(true)
    }

    fmt.Println("Done!")
}
