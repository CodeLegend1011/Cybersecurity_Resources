# Active Reconnaissance: Information Gathering

**Active reconnaissance** involves direct interaction with the target system to gather information about open ports, services, and operating systems. This type of reconnaissance is detectable by the target system since it sends probes to gather data. It helps penetration testers or attackers understand how to exploit the system.

## 1. **Port Scanning** and Techniques

Port scanning is a crucial part of active reconnaissance to identify **open, closed, or filtered ports** on a target machine. This information reveals the services running on a machine and identifies potential attack vectors.

### 1.1 **TCP 3-Way Handshake and Port Interaction**

To understand how various scans work, it's essential to see how a typical **TCP connection** happens:
1. **SYN** → Target (Sends a Synchronization request to initiate connection)
2. **← SYN-ACK** (Target responds if the port is open)
3. **ACK** → Target (Acknowledgment completes the connection)

If a **port is closed**:
1. **SYN** → Target
2. **← RST (Reset)** (Port is closed, so the target denies connection)

### 1.2 **Port Scanning Techniques**

Port scans send specially crafted packets to the target’s ports and analyze the responses to determine whether they are **open**, **closed**, or **filtered**. Different types of port scans achieve different results:

#### **SYN Scan (-sS)** (Half-open scan)
- **SYN** → Target
- **← SYN-ACK** (if the port is open)
- **RST** → Target (Scanner immediately resets the connection, never completes handshake)

**Purpose**: This scan is **stealthy** because the connection never completes, avoiding some firewalls and intrusion detection systems (IDS).

#### **TCP Connect Scan (-sT)**
- This scan performs a **full 3-way handshake** with the target.
- **SYN** → Target  
- **← SYN-ACK** (if port is open)  
- **ACK** → Target (Completes the handshake)

**Purpose**: It’s easier to detect because the connection completes fully. Useful when the user does not have raw socket access to send custom packets (as with SYN scans).

#### **UDP Scan (-sU)**
- Sends **UDP packets** to the target's ports.
- If a **UDP port is closed**, the target responds with an **ICMP Port Unreachable** message.
- If there is **no response**, the port is likely **open** or **filtered**.

**Purpose**: Identifies services running on **UDP ports** (e.g., DNS on port 53 or SNMP on port 161).

#### **TCP FIN Scan (-sF)**  
- **FIN** → Target (Sends a TCP FIN packet without establishing a connection)
- **← No Response** if the port is open (RFC-compliant behavior).
- **← RST** if the port is closed.

**Purpose**: Bypasses firewalls that allow only SYN packets. Often used to detect **firewall and IDS evasion techniques**.

---

## 2. **Nmap Scan Types and Implementation**

Nmap is one of the most powerful tools for **active reconnaissance**, supporting various scan types to discover hosts, ports, and services. Below are **Nmap scan types** and their **usage**.

### 2.1 **TCP Connect Scan (-sT)**  
- Command:  
  ```bash
  nmap -sT <target>
  ```

- **Purpose**: Used when the user does not have raw socket privileges. It performs a full 3-way handshake for connection.

### **TCP Connect Scan (-sT)**  
1. **SYN** → Target  
2. **← SYN-ACK** (if open) / **← RST** (if closed)  
3. **ACK** → Target (Completes the handshake)  
4. **RST** → Target (Closes the connection)

---

### 2.2 **UDP Scan (-sU)**
- Command:  
  ```bash
  nmap -sU <target>
  ```

- **Purpose**: Identifies open UDP ports. Requires more time since UDP does not respond as reliably as TCP, making it slower and prone to false positives.

---

### 2.3 **TCP SYN Scan (-sS)**  
- Command:  
  ```bash
  nmap -sS <target>
  ```

- **Purpose**: Performs a **half-open** scan by sending a SYN packet and analyzing the response. It’s faster and stealthier than a full TCP connect scan.

### **SYN Scan (-sS)**  
1. **SYN** → Target  
2. **← SYN-ACK** (if open) / **← RST** (if closed)  
3. **RST** → Target (Scan terminates the connection)

---

### 2.4 **TCP FIN Scan (-sF)**
- Command:  
  ```bash
  nmap -sF <target>
  ```

- **Purpose**: Used to evade firewalls by sending FIN packets. Effective against some targets that only block SYN packets.

### **TCP FIN Scan (-sF)**  
1. **FIN** → Target  
2. **← No Response** (if open) / **← RST** (if closed)

---

### 2.5 **Host Discovery Scan (-sn)**
- Command:  
  ```bash
  nmap -sn <target>
  ```

- **Purpose**: This scan does **host discovery** only, without checking ports. It helps identify live hosts on the network.

### **Host Discovery Scan (-sn)**  
1. **ICMP Echo Request** → Target  
2. **← ICMP Echo Reply** (if host is alive)

---

### 2.6 **Timing Options (-T 0 to -T 5)**

Nmap provides **timing templates** to control the speed of scans. Depending on the target and network environment, users can adjust the timing to avoid detection or improve performance.

- **Command**:  
  ```bash
  nmap -T4 <target>
  ```

- **Timing Levels**:
  - **T0 (Paranoid)**: Extremely slow to avoid IDS detection.
  - **T1 (Sneaky)**: Very slow scan to avoid raising alerts.
  - **T2 (Polite)**: Reduces the impact on network traffic.
  - **T3 (Normal)**: Default speed.
  - **T4 (Aggressive)**: Faster scanning, might trigger IDS alerts.
  - **T5 (Insane)**: Very fast but likely to be detected.

---


# Enumeration: Overview

**Enumeration** is the process of gathering detailed information about the target system, network, or service by actively probing it. It aims to extract usernames, group memberships, services, shares, configurations, and more. Attackers or penetration testers use this information to find potential attack vectors.

### Types of Enumeration

1. **Host Enumeration**
2. **User Enumeration (e.g., SMB users)**
3. **Group Enumeration**
4. **Network Share Enumeration**
5. **Service Enumeration**
6. **Web Application Enumeration**
7. **Enumeration via Packet Crafting**

---

## 1. **Host Enumeration**

Host enumeration helps identify the **active hosts** on a network and the services they expose.  
**Commands**:
```bash
nmap -sn 192.168.88.0/24  # Ping sweep to discover live hosts
nmap -Pn 192.168.88.251   # Scan without ping to avoid ping filtering
```

- **Implementation**:  
  This reveals the **IP addresses of active hosts** and the presence of open ports.  
  Use **ICMP Echo Requests** and **ARP requests** to discover live systems.

---

## 2. **User Enumeration (SMB Message Illustration)**

SMB (Server Message Block) protocol is used for file sharing and allows **user enumeration** by probing for usernames on the target host.

### Example of Enumerating SMB Users with **Nmap**:
```bash
nmap --script smb-enum-users.nse 192.168.88.251
```

- **Explanation**:  
  This Nmap script retrieves a **list of users** by connecting to the SMB service. The SMB protocol communicates via port **445**, and the response may include usernames, shares, or even login prompts.

### **SMB Message Flow Illustration**:
1. **Request**:  
   SMB client sends a **Session Setup Request** with user credentials (or guest access request) →  
2. **Response**:  
   Target replies with a **Session Setup Response** containing a list of **valid usernames** (if guest or anonymous access is allowed).

---

## 3. **Group Enumeration**

Group enumeration allows discovering **user groups** in a network, such as **administrators, guests, or developers**.

### Example with Nmap:
```bash
nmap --script smb-enum-groups.nse -p445 192.168.88.251
```

- **Explanation**:  
  This script queries the SMB service for **group membership** information, which may reveal **privileged groups** like "Admins" or "Domain Users."

---

## 4. **Network Share Enumeration**

Network share enumeration focuses on identifying shared **folders or resources** on the network.

### Example Commands:
```bash
nmap --script smb-enum-shares.nse -p 445 192.168.88.251
smbclient -L \\192.168.88.251   # List shares without authentication
```

- **Explanation**:  
  This reveals the list of **shared directories** or resources exposed on the host. If any **misconfigured share** allows unauthorized access, it can be exploited.

### Additional Example: Using `enum4linux`
```bash
enum4linux 192.168.88.251
./enum4linux-ng.py -As 192.168.88.251
```

- **Explanation**:  
  **`enum4linux`** is a tool designed for enumerating **Windows systems** via SMB, providing information like users, shares, OS versions, and policies.

---

## 5. **Web Page / Web Application Enumeration**

Web enumeration extracts information about the **web server, applications, or directories** hosted on a target machine. 

### Example Commands:
```bash
nmap -sV --script=http-enum -p 80 192.168.88.251
nikto -h 192.168.88.251
```

- **Explanation**:
  - **`nmap -sV`** identifies the **service versions** running on the target web server.
  - **`http-enum`** script searches for known **directories** (like `/admin`, `/login`).
  - **`Nikto`** performs a vulnerability scan, identifying **misconfigurations** or known CVEs (e.g., outdated software).

---

## 6. **Service Enumeration**

Service enumeration focuses on gathering information about the **processes or services** running on a target machine. 

### Example Nmap Command:
```bash
nmap --script smb-enum-processes.nse --script-args smbusername=<username>,smbpass=<password> -p445 192.168.88.251
```

- **Explanation**:  
  This command enumerates **running processes** on the target machine via SMB. Information like **service names** and **process IDs** can be obtained, which might reveal potential attack points.

---

## 7. **Enumeration via Packet Crafting**

Packet crafting enables customized packets to **probe services or protocols** beyond standard scans. Tools like **Scapy** are used to **create and send packets**.

### Example: Using Scapy to Send ICMP Packets
```python
from scapy.all import *
send(IP(dst="192.168.88.251")/ICMP()/"malicious_payload")
```

- **Explanation**:  
  This command sends a **custom ICMP packet** to the target. Packet crafting can help bypass **firewall rules** or probe responses that regular tools cannot.

---

### Example: **Using Wireshark or Tshark for Packet Analysis**
```bash
sudo tshark host 192.168.78.142
```

- **Explanation**:  
  **Tshark** captures packets between the scanning system and the target to analyze responses. It helps visualize **network behavior**, such as how the server reacts to enumeration attempts.

---

## Summary

| **Enumeration Type**           | **Command / Tool**                                                  | **Description**                                   |
|--------------------------------|----------------------------------------------------------------------|-------------------------------------------------|
| Host Enumeration               | `nmap -sn`                                                           | Identify live hosts on the network               |
| User Enumeration               | `nmap --script smb-enum-users.nse`                                   | List users via SMB                              |
| Group Enumeration              | `nmap --script smb-enum-groups.nse`                                  | Identify user groups                            |
| Network Share Enumeration      | `nmap --script smb-enum-shares.nse`, `smbclient`                     | Discover shared resources                       |
| Web Application Enumeration    | `nmap --script=http-enum`, `nikto`                                   | Identify directories, services, and vulnerabilities |
| Service Enumeration            | `nmap --script smb-enum-processes.nse`                               | List running processes via SMB                  |
| Packet Crafting                | `scapy`, `send(IP()/ICMP())`, `tshark`                               | Custom packet generation and capture            |

---

### TCPDump and Wireshark: Capturing and Analyzing Network Traffic

**Objective**: Use `tcpdump` to capture network traffic, save it to a file, and analyze it with Wireshark.

---

### Part 1: Capture and Save Network Traffic with TCPDump

**Step 1**: Start TCPDump
1. Open a terminal.
2. Check network interfaces with:
   ```bash
   ifconfig
   ```
3. Identify your primary interface (e.g., `eth0`).
4. Start capturing on this interface with `tcpdump`, saving the output to a `.pcap` file:
   ```bash
   sudo tcpdump -i eth0 -s 0 -w packetdump.pcap
   ```
   - `-i eth0`: Captures traffic on `eth0`.
   - `-s 0`: Captures the full packet.
   - `-w packetdump.pcap`: Writes output to `packetdump.pcap`.

**Step 2**: Generate Network Traffic
- Open a browser and visit a website (e.g., `google.com` or `skillsforall.com`) to generate HTTP traffic.
- Press `CTRL+C` in the terminal to stop the capture.

**Step 3**: Verify the Capture
- List the `.pcap` file to ensure it was saved:
   ```bash
   ls packetdump.pcap
   ```

---

### Part 2: View and Analyze with Wireshark

**Step 1**: Open Wireshark
- Open Wireshark from the terminal:
  ```bash
  wireshark
  ```
- In Wireshark, open `packetdump.pcap` from `File -> Open`.

**Step 2**: Analyze DNS Traffic
1. Filter DNS traffic by typing `dns` in the filter bar.
2. Observe DNS queries and responses to see requested websites.

**Step 3**: Analyze HTTP Session
1. Search for `POST` to find HTTP login requests.
2. Expand `HTML Form URL Encoded` to view login details (e.g., `username` and `password` fields).

3. To examine session cookies:
   - Search for `302 Found` to locate `Set-Cookie` headers.
   - Compare `PHPSESSID` values to see if they match between server and client packets.

---
