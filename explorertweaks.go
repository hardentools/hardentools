/*
    Hardentools
    Copyright (C) 2017  Claudio Guarnieri, Mariano Graziano, Ashley Hull

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
    "golang.org/x/sys/windows/registry"
)

// Explorer

/*
- HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer
 */
func trigger_explorertweaks(enable bool) {
    key_explorertweaks, _, _ := registry.CreateKey(registry.CURRENT_USER, "SYSTEM\\Microsoft\\Windows\\CurrentVersion\\Explorer", registry.WRITE)
    key_explorertweaksAdvanced, _, _ := registry.CreateKey(registry.CURRENT_USER, "SYSTEM\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced", registry.WRITE)
    
    if enable {
        events.AppendText("Enabling Explorer Tweaks\n")
        key_explorertweaksAdvanced.SetDWordValue("HideFileExt", 0x00000000)
        key_explorertweaksAdvanced.SetDWordValue("Hidden", 0x00000001)
        key_explorertweaksAdvanced.SetDWordValue("ShowSuperHidden", 0x00000001)
    } else {
        events.AppendText("Disabling Explorer Tweaks\n")
        key_explorertweaksAdvanced.SetDWordValue("HideFileExt", 0x00000001)
        key_explorertweaksAdvanced.SetDWordValue("Hidden", 0x00000002)
        key_explorertweaksAdvanced.SetDWordValue("ShowSuperHidden", 0x00000000)
    }

    key_explorertweaks.Close()
    key_explorertweaksAdvanced.Close()
}

// Notes:
// Support: 
