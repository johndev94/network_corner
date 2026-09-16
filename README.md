# Network Corner

Network Corner is a compact, always-on-top Windows utility for router and network testing. It continuously shows IPv4 details for Wi-Fi and Ethernet adapters and lets a technician apply a static IPv4 configuration or switch an adapter back to DHCP.

## Run

Double-click `NetworkCorner.exe`. Choose the monitor and corner from the bottom of the panel. Enable **Stretch panel to full monitor height** when you want the utility to occupy the full vertical edge of that monitor; disable it to return to the compact panel.

Use the standard title-bar minimize button to place Network Corner on the Windows taskbar. Select it from the taskbar to restore the panel.

Each adapter heading shows both its connection status and how Windows assigns its IPv4 address, for example `[Connected • Dynamic / DHCP]` or `[Connected • Static]`. Wi-Fi, Ethernet, DHCP, and static states use distinct colours for quick recognition.

**Hide down adapters** is enabled by default, removing disconnected adapters from the information panel, adapter editor, and Nmap network selector. Disable it to show every detected Wi-Fi and Ethernet adapter again.

The adapter-information area grows with the window. Drag the top or bottom window edge to give it more room, or enable full-height mode to use all remaining vertical space for adapter details.

## Nmap scanning

Open the **Nmap Scan** tab and choose the Wi-Fi or Ethernet interface under **Adapter**. Network Corner maps the Windows adapter to Nmap's capture interface and forces the scan through it. **Target mode** offers the adapter's gateway IP, its complete calculated CIDR network, or a manual hostname, IP address, or CIDR range. Four presets are available:

- **Discover devices** finds responsive hosts without scanning ports.
- **Quick ports** checks the 100 most common TCP ports.
- **Standard ports** runs Nmap's standard TCP port selection.
- **Services + versions** checks common ports and identifies listening services.

**Use gateway** copies the selected network adapter's current gateway into the scan target. Scan results stream into the output panel and an active scan can be cancelled. Only scan networks and devices you are authorised to test.

## Ping monitor

Open the **Ping** tab, choose an adapter, and select its **Gateway IP** or a **Manual target**. Network Corner binds ping to the selected adapter's IPv4 source address. With **Continuous ping** disabled, it sends four pings and stops. Enable the checkbox to keep pinging until **Stop** is pressed. Output streams into the panel as it arrives.

## Telnet and SSH

Open the **Telnet / SSH** tab, choose an adapter, select its **Gateway IP** or a **Manual target**, then choose a protocol and port. You can optionally provide an SSH username. SSH is bound to the selected adapter's IPv4 source address; Telnet follows Windows routing. **Open connection** launches the installed Windows client in a separate interactive terminal. Network Corner never collects or stores terminal passwords.

## Network diagnostics

The **Diagnostics** tab provides DNS lookup, traceroute, TCP port testing, public IP lookup, ARP table, routing table, and an elevated DNS-cache flush. Long-running command output streams into the results panel and can be stopped.

To change settings:

1. Choose the Wi-Fi or Ethernet adapter under **Edit**.
2. Enter the IP address, subnet mask, optional gateway, and optional DNS servers.
3. Click **Apply static**. Windows asks for administrator approval only at this point.

Click **Use DHCP** to return the selected adapter's address and DNS configuration to automatic assignment.

Use **Release IP** and **Renew IP** to release or renew the selected adapter's DHCP lease. **Refresh IP** immediately reloads the displayed adapter configuration without waiting for the automatic refresh interval.

Profiles store commonly used lab configurations. Fill in the fields, click **Save current**, and give the configuration a name. Selecting that profile later fills all fields; click **Apply static** to activate it.

The built-in **TFTP** profile uses IP `192.168.1.10`, subnet mask `255.255.255.0`, gateway `192.168.1.1`, primary DNS `8.8.8.8`, and secondary DNS `8.8.4.4`.

## Safety behavior

- Every change requires confirmation and a Windows administrator prompt.
- Input is validated as IPv4 before Windows settings are touched.
- Release and Renew are available only when the selected adapter uses DHCP.
- Before applying a different static address, Network Corner checks whether it responds or is already assigned to another local adapter and warns about a possible conflict.
- Changing an active adapter can temporarily disconnect the computer.
- Profiles are stored per user in `%LOCALAPPDATA%\NetworkCorner\profiles.json`.
- The utility changes IPv4 only. IPv6 is not modified.

Adapter selection is synchronized across the Network, Nmap, Ping, and Telnet/SSH tabs. Changing it in any tab updates the others.

Window size, selected monitor and corner, full-height mode, hidden-adapter preference, selected adapter, and selected tab are saved per user in `%LOCALAPPDATA%\NetworkCorner\settings.json`.

## Rebuild

Right-click `build.ps1`, choose **Run with PowerShell**, or run:

```powershell
powershell -ExecutionPolicy Bypass -File .\build.ps1
```

The build uses the C# compiler included with Windows and needs no SDK or third-party packages.
