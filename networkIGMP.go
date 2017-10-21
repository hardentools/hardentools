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

// IGMP

/*
- HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters
 */
func trigger_networkIGMP(enable bool) {
    key_networkIGMP, _, _ := registry.CreateKey(registry.LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters", registry.WRITE)
    
    if enable {
        events.AppendText("Enabling IP multicast packets (participate in IGMP)\n")
        key_networkIGMP.SetDWordValue("IGMPLevel", 2)
    } else {
        events.AppendText("Disabling IP multicast packets (participate in IGMP)\n")
        key_networkIGMP.SetDWordValue("IGMPLevel", 0)
    }

    key_networkIGMP.Close()
}

// Notes:
// Support: https://technet.microsoft.com/en-us/library/cc957547.aspx
