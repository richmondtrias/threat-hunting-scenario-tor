<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/richmondtrias/threat-hunting-scenario-tor/blob/main/threat-hunting-scenario-tor-event-creation.md)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

##  Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

Searched the DevceFileEvents table for ANY file that had the string “tor” in it and discovered what looks like the user “labuservm” downloaded a tor installer, did something that resulted in many tor-related files being copied to the desktop and the creation of a file called “tor-shipping-list.txt” on the desktop at 2025-03-20T21:41:46.2166375Z. These events began at: 2025-03-20T21:31:29.4324114Z

**Query used to locate events:**

```kql
DeviceFileEvents
| where FileName contains "tor"
| where InitiatingProcessAccountName == "labuservm"
| where DeviceName == "mon2-vm"
| where Timestamp >= datetime(2025-03-20T21:31:29.4324114Z)
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName

```
![image](https://github.com/user-attachments/assets/dc064766-a787-4d80-848c-d7578c7f5cb0)


---

### 2. Searched the `DeviceProcessEvents` Table

Searched the DeviceProcessEvents table for any ProcessCommandLine that contained the string “Tor-browser-windows-x86_64-portable-14.0.7.exe”. Based on the logs returned, at 2025-03-20T21:32:47.1098554Z from their Downloads folder, using a command that triggered a silent installation.

**Query used to locate event:**

```kql

DeviceProcessEvents
| where DeviceName == "mon2-vm"
| where ProcessCommandLine contains "tor-browser"
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine

```
![image](https://github.com/user-attachments/assets/28f71212-292c-4e15-8f5e-cf6fcbb8ff35)


---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched the DeviceProcessEvents table for any indication that user “labuservm” actually opened the tor browser. There was evidence that they did open it on 2025-03-20T21:33:21.992861Z. There were several other instances of firefox.exe (Tor) as well as tor.exe spawned afterwards.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName == "mon2-vm"
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
| order by Timestamp desc

```
![image](https://github.com/user-attachments/assets/ca4f13ce-8a5c-4b55-b27b-9bed9ea76d78)


---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched the DeviceNetworkEvents table for any indication the tor browser was used to establish a connection using any of the known tor ports.
At 2025-03-20T21:33:56.6470454Z, the mon2-vm virtual machine, operated by the labuservm account, successfully established a network connection. The connection was made using Tor (tor.exe), located in the Tor Browser folder on the desktop. It connected to the remote IP address 141.105.130.119 on port 9001, which is commonly used for Tor network communications. There were a couple other connections to sites over port 443.

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName == "mon2-vm"
| where InitiatingProcessAccountName != "system"
| where InitiatingProcessFileName in ("tor.exe", "firefox.exe")
| where RemotePort in ("9001", "9030", "9040", "9050", "9051", "9150", "80", "443")
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName
, InitiatingProcessFolderPath
| order by Timestamp desc

```
![image](https://github.com/user-attachments/assets/d8a46387-d287-4d70-bc5d-4042e6c11b1f)


---

## Chronological Event Timeline 

Tor Browser Download (2025-03-20 16:31:29 UTC)


The user "labuservm" on the virtual machine "mon2-vm" downloaded the Tor Browser installer (tor-browser-windows-x86_64-portable-14.0.7.exe) into the Downloads folder.
Tor Browser Execution (2025-03-20 16:32:47 UTC)


The user executed the Tor Browser installer with a silent installation (/S command), meaning it was installed without user prompts.
Tor Browser Files Copied to Desktop (2025-03-20 16:33:05 UTC)


Various Tor-related files, including Tor.txt, Torbutton.txt, and Tor-Launcher.txt, were created/copied to the Desktop\Tor Browser\Browser directory.
Tor Browser Launched (2025-03-20 16:33:21 UTC)


The user opened the Tor Browser, as evidenced by process events showing the execution of tor.exe and firefox.exe (Tor’s modified version of Firefox).
Tor Network Connection Established (2025-03-20 16:33:56 UTC)


The Tor process (tor.exe) established a network connection to 141.105.130.119 on port 9001, a standard Tor entry node.
Additional connections to websites over port 443 (HTTPS) were detected.
Tor-related File Created (2025-03-20 16:41:46 UTC)


A file named tor-shipping-list.txt was created on the desktop, possibly indicating further use or documentation related to Tor.

---

## Summary

The user "labuservm" on the "mon2-vm" device initiated and completed the installation of the TOR browser. They proceeded to launch the browser, establish connections within the TOR network, and created various files related to TOR on their desktop, including a file named `tor-shopping-list.txt`. This sequence of activities indicates that the user actively installed, configured, and used the TOR browser, likely for anonymous browsing purposes, with possible documentation in the form of the "shopping list" file.

---

## Response Taken

TOR usage was confirmed on the endpoint `mon2-vm` by the user `labuservm`. The device was isolated, and the user's direct manager was notified.

---
