# Network Corner

Network Corner is a compact, always-on-top Windows utility for router and network testing. It continuously shows IPv4 details for Wi-Fi and Ethernet adapters and lets a technician apply a static IPv4 configuration or switch an adapter back to DHCP.

## Run

Double-click `NetworkCorner.exe`. Choose the monitor and corner from the bottom of the panel. Enable **Stretch panel to full monitor height** when you want the utility to occupy the full vertical edge of that monitor; disable it to return to the compact panel.

Each adapter heading shows both its connection status and how Windows assigns its IPv4 address, for example `[Connected • Dynamic / DHCP]` or `[Connected • Static]`. Wi-Fi, Ethernet, DHCP, and static states use distinct colours for quick recognition.

The adapter-information area grows with the window. Drag the top or bottom window edge to give it more room, or enable full-height mode to use all remaining vertical space for adapter details.

## Nmap scanning

Open the **Nmap Scan** tab and choose a detected Wi-Fi or Ethernet subnet from **Network**. Network Corner calculates the correct CIDR range from that adapter's current IP address and subnet mask. Choose **Manual target** to scan a custom hostname, individual IP address, or CIDR range. Four presets are available:

- **Discover devices** finds responsive hosts without scanning ports.
- **Quick ports** checks the 100 most common TCP ports.
- **Standard ports** runs Nmap's standard TCP port selection.
- **Services + versions** checks common ports and identifies listening services.

**Use gateway** copies the selected network adapter's current gateway into the scan target. Scan results stream into the output panel and an active scan can be cancelled. Only scan networks and devices you are authorised to test.

To change settings:

1. Choose the Wi-Fi or Ethernet adapter under **Edit**.
2. Enter the IP address, subnet mask, optional gateway, and optional DNS servers.
3. Click **Apply static**. Windows asks for administrator approval only at this point.

Click **Use DHCP** to return the selected adapter's address and DNS configuration to automatic assignment.

Profiles store commonly used lab configurations. Fill in the fields, click **Save current**, and give the configuration a name. Selecting that profile later fills all fields; click **Apply static** to activate it.

## Safety behavior

- Every change requires confirmation and a Windows administrator prompt.
- Input is validated as IPv4 before Windows settings are touched.
- Changing an active adapter can temporarily disconnect the computer.
- Profiles are stored per user in `%LOCALAPPDATA%\NetworkCorner\profiles.json`.
- The utility changes IPv4 only. IPv6 is not modified.

## Rebuild

Right-click `build.ps1`, choose **Run with PowerShell**, or run:

```powershell
powershell -ExecutionPolicy Bypass -File .\build.ps1
```

The build uses the C# compiler included with Windows and needs no SDK or third-party packages.
