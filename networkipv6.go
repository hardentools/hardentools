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
    "golang.org/x/sys/windows/registry"
)

// IPv6

/*
- HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\TCPIP6\Parameters\
 */
func trigger_networkipv6(enable bool) {
    key_tcpip6parameters, _, _ := registry.CreateKey(registry.LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\TCPIP6\\Parameters", registry.WRITE)
    
    if enable {
        events.AppendText("Enabling IPv6\n")
        key_tcpip6parameters.DeleteValue("DisabledComponents")
    } else {
        events.AppendText("Disabling IPv6y\n")
        key_tcpip6parameters.SetDWordValue("DisabledComponents", 0xff)
    }

    key_tcpip6parameters.Close()
}

// Notes: 0xff to disable all IPv6 components except the IPv6 loopback interface. This value also configures Windows to prefer using IPv4 over IPv6 by changing entries in the prefix policy table.
// Support: https://support.microsoft.com/en-us/help/929852/how-to-disable-ipv6-or-its-components-in-windows
