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

// SSDP

/*
- HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\DirectPlayNATHelp\DPNHUPnP
 */
func trigger_networkSSDP(enable bool) {
    key_networkSSDP, _, _ := registry.CreateKey(registry.LOCAL_MACHINE, "SYSTEM\\Microsoft\\DirectPlayNATHelp\\DPNHUPnP", registry.WRITE)
    
    if enable {
        events.AppendText("Enabling Simple Service Discovery Protocol (SSDP)\n")
        key_networkSSDP.DeleteValue("UPnPMode")
    } else {
        events.AppendText("Disabling Simple Service Discovery Protocol (SSDP)\n")
        key_networkSSDP.SetDWordValue("UPnPMode", 2)
    }

    key_networkSSDP.Close()
}

// Notes: If you set UPnPMode to 2, Universal Plug and Play Network Address Translation (NAT) traversal discovery does not occur. 
// Support: https://support.microsoft.com/en-us/help/317843/traffic-is-sent-after-you-turn-off-the-ssdp-discover-service-and-universal-plug-and-play-device-host
