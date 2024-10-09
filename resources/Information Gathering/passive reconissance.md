# Passive Reconnaissance

## Overview

**Passive reconnaissance** is a crucial initial step in penetration testing, where the tester gathers intelligence about the target without directly engaging with it. The aim is to remain undetected while collecting valuable information that may reveal potential weaknesses in the target’s infrastructure.

Unlike active reconnaissance, passive methods rely on publicly available data and third-party resources, ensuring that the target remains unaware of the tester’s activities. This phase provides valuable insights into the target’s digital footprint, technologies used, employees, and more.

## Why Use Passive Reconnaissance?

- **Stealth**: Since there is no direct interaction with the target, passive reconnaissance activities are undetectable by standard security measures.
- **Context Building**: Collects external data to provide context about the target’s security posture before active testing.
- **Reduced Risk**: Avoids triggering alarms in intrusion detection systems (IDS) or intrusion prevention systems (IPS).

---

## Tools for Passive Reconnaissance

### 1. **OSINT Framework**

The [OSINT Framework](https://osintframework.com/) is an open-source project that organizes free online resources for conducting open-source intelligence. It provides a structured collection of tools for gathering information on IP addresses, domain names, social media accounts, and much more.

#### Key Features:
- Organized tree-based structure.
- Links to hundreds of OSINT tools and services.
- Focus on passive reconnaissance without engaging the target.

**Example Categories in OSINT Framework**:
- Domain name lookups
- Email address searches
- IP geolocation
- Social media profiling

---

### 2. **SpiderFoot**

**SpiderFoot** is a powerful OSINT tool used to automate the process of gathering intelligence from multiple public sources about a target. It supports integration with more than 100 data sources, including domain names, IP addresses, email addresses, and more.

#### Key Features:
- Extensive OSINT collection from over 100 sources.
- Fully automated reconnaissance tool with a web-based interface.
- Capable of identifying potential vulnerabilities without interacting with the target.

#### SpiderFoot Installation on Kali Linux:

**Step 1: Install SpiderFoot**:

SpiderFoot is available as a Docker image or via `pip` for manual installation.

```bash
sudo apt update
sudo apt install spiderfoot
```

**Step 2: Start the SpiderFoot Web Interface**:

Once installed, run SpiderFoot with the following command to launch the web-based GUI on Kali:

```bash
spiderfoot -l 127.0.0.1:5001
```

You can access the GUI via your browser at `http://localhost:5001`.

#### SpiderFoot API Integration:

SpiderFoot can be integrated into a larger automated OSINT process via its REST API. Below is an example of initiating a scan using the API in Python:

```python
import requests

api_url = "http://localhost:5001/start_scan"
data = {
    'target': 'example.com',
    'modules': 'all'
}

response = requests.post(api_url, data=data)
print(response.json())
```

---

### 3. **Recon-ng**

**Recon-ng** is a powerful reconnaissance framework modeled after Metasploit. It automates the process of gathering information through various modules, allowing for efficient OSINT collection.

#### Key Features:
- Modular design to add/remove OSINT sources.
- Simple command-line interface.
- API support for data sources like Shodan, Google, and Twitter.

#### Recon-ng Installation and Usage on Kali Linux:

**Step 1: Install Recon-ng**:

Recon-ng comes pre-installed in Kali Linux. If you need to update or install it:

```bash
sudo apt install recon-ng
```

**Step 2: Start Recon-ng**:

```bash
recon-ng
```

**Step 3: Create a Workspace**:

Workspaces help organize different reconnaissance tasks:

```bash
workspace create target_recon
```

**Step 4: Running a Module**:

You can search for and run modules to gather information. For example, using the `whois_poc` module to gather whois information about a target domain:

```bash
modules load recon/domains-hosts/whois_poc
set SOURCE example.com
run
```

[Recon-ng Documentation](https://github.com/lanmaster53/recon-ng/wiki)

---

### 4. **theHarvester**

**theHarvester** is a simple yet effective tool for gathering email addresses, subdomains, IPs, and URLs using search engines and public sources. It's commonly used to enumerate potential attack vectors.

#### Key Features:
- Collects data from search engines like Google, Bing, and more.
- Can gather email addresses, subdomains, and other information quickly.

#### Installation and Usage:

**Step 1: Install theHarvester**:

theHarvester comes pre-installed in Kali Linux. To install it manually or update:

```bash
sudo apt install theharvester
```

**Step 2: Run theHarvester**:

```bash
theHarvester -d example.com -l 500 -b google
```

This command will search Google for the domain `example.com` and return up to 500 results.

---

### 5. **Maltego**

**Maltego** is a sophisticated graphical link analysis tool that connects data from numerous sources to reveal relationships between people, domains, email addresses, and more. It’s ideal for visualizing connections during OSINT operations.

#### Key Features:
- Visual link analysis tool for connecting entities like domains, people, and emails.
- Integrates with numerous data sources for thorough OSINT.
- Graph-based interface for easy pattern recognition.

#### Installation and Usage:

Maltego can be installed and run on Kali Linux using:

```bash
sudo apt install maltego
```

You will need to register for an account and log in to the interface to start visualizing data. Maltego transforms data into a graphical representation that helps in identifying patterns and connections across the gathered data.

---

### 6. **Shodan**

**Shodan** is an invaluable search engine for finding devices connected to the internet. It helps gather information about servers, IoT devices, cameras, and other internet-exposed services.

#### Key Features:
- Search for devices and services exposed to the internet.
- Explore open ports, services, and technologies used by targets.
- Provides APIs for automation.

#### Shodan on Kali Linux:

While Shodan doesn’t have a direct installation, you can use the **Shodan API** in Python for passive reconnaissance:

```bash
pip install shodan
```

#### Shodan API Example:

```python
import shodan

api = shodan.Shodan('YOUR_API_KEY')

# Search for open ports or services on a target IP
results = api.search('example.com')

for result in results['matches']:
    print(f"IP: {result['ip_str']}, Port: {result['port']}, Data: {result['data']}")
```

[Shodan Documentation](https://www.shodan.io/)

---

### 7. **Amass**

**Amass** is a powerful tool for in-depth passive reconnaissance of DNS. It can help map out external network resources and subdomains belonging to a target organization.

#### Key Features:
- Gathers data from passive DNS databases.
- Discovers subdomains, IPs, and other DNS-related information.
- Supports both active and passive recon.

#### Installation and Usage:

Amass is pre-installed on Kali Linux but can be installed or updated manually:

```bash
sudo apt install amass
```

**Basic Usage**:

```bash
amass enum -d example.com
```

This will enumerate subdomains of `example.com` using passive methods.

[Amass Documentation](https://github.com/OWASP/Amass)

---

### 8. nslookup

`nslookup` is a network administration command-line tool used for querying the Domain Name System (DNS) to obtain domain name or IP address mapping, or other DNS records.

### Usage:

```bash
nslookup example.com
```

This command will query the DNS for `example.com` and return the associated IP address.

---

### 9. dnslookup

`dnslookup` is another tool used for DNS lookups. It provides detailed information about the domain’s DNS records, including `A`, `MX`, `NS`, and other record types.

### Usage:

```bash
dnslookup example.com
```

This will return DNS records for the target domain.

---

### 10. dig

`dig` (Domain Information Groper) is a powerful tool for DNS queries. It is often used to query DNS name servers and to troubleshoot DNS problems.

### Usage:

```bash
dig example.com
```

This will return detailed DNS information for `example.com`, including `A`, `MX`, `NS` records, and more.

---

### 11. whois

`whois` is used to retrieve registration details about domain names, IP addresses, or autonomous system numbers from a public database.

### Usage:

```bash
whois example.com
```

This will display information about the owner of `example.com`, including registration details, contact information, and more.

---


### 12. **host Command**
The `host` command is a simple utility used for performing DNS lookups. It allows users to query different types of DNS records such as A, MX, NS, and more.

#### Example:
```bash
host example.com
```
This will return the IP address associated with the domain `example.com`.

To query a specific record type, such as an MX (Mail Exchange) record:
```bash
host -t MX example.com
```
This will return the mail servers for `example.com`.

---

### 13. **Reverse DNS (rDNS)**
Reverse DNS (rDNS) is the process of resolving an IP address back to a domain name. This is the opposite of the usual DNS lookup, which resolves a domain name to an IP address. The `-x` flag is used for reverse DNS lookups with utilities like `host` and `dig`.

#### Example with `host`:
```bash
host 8.8.8.8
```
This returns the domain name for Google's public DNS server `8.8.8.8`.

#### Example with `dig`:
```bash
dig -x 8.8.8.8
```
This command returns the PTR record, showing the domain associated with the IP address.

---

### 14. **HSRP (Hot Standby Router Protocol)**
HSRP is a Cisco protocol that provides high availability by allowing routers to back each other up in case one fails. It is not directly related to DNS, but it’s often used in network setups to ensure redundancy.

- HSRP allows two or more routers to share an IP address, with one router being the "active" router that handles traffic, and another acting as a "standby" in case the active router fails.
- HSRP is commonly used in large enterprise networks to minimize downtime.

While HSRP isn’t directly queryable with commands like `host` or `dig`, understanding how it works is important for network redundancy and resilience.

---

### 15. **Using `-x` Flag for Reverse DNS Lookups**
The `-x` flag is used with DNS lookup tools like `dig` and `host` to perform reverse DNS queries, which are useful when you want to determine the domain name associated with an IP address.

#### Example with `host`:
```bash
host -x 8.8.8.8
```
This returns the PTR (Pointer) record that maps the IP address to the domain name.

#### Example with `dig`:
```bash
dig -x 8.8.8.8
```
This will also return the PTR record, showing the domain associated with the IP address `8.8.8.8`.

---

# SSL Tools and Cryptographic Flaws

## 1. SSL Tools

| **Tool**      | **Description**                                                         | **Recon, Exploitation, or Utility** |
|---------------|-------------------------------------------------------------------------|-------------------------------------|
| **sslscan**   | Queries SSL services to determine what cyphers are supported             | Reconnaissance                      |
| **ssldump**   | Analyze and decode SSL traffic                                           | Exploitation                        |
| **sslh**      | Running multiple services on port 443                                    | Utility                             |
| **sslsplit**  | Enable Man-in-the-Middle (MitM) attacks on SSL encrypted network connections | Exploitation                    |
| **sslyze**    | Analyze the SSL configuration of a server by connecting to it            | Reconnaissance                      |

## 2. Cryptographic Flaws and Weak Implementations

Digital certificates contain a wealth of information that can help identify cryptographic flaws or weak implementations. Information often found within digital certificates includes:

- **Certificate Serial Number**
- **Subject Common Name**
- **Uniform Resource Identifier (URI)**
- **Organization Name**
- **Online Certificate Status Protocol (OCSP) Information**
- **Certificate Revocation List (CRL) URI**

These attributes can reveal weaknesses in encryption or configuration, helping to identify vulnerable services.

### Common SSL Vulnerabilities:
- **Weak Cipher Suites**: Use of outdated cryptographic algorithms such as SSLv2 and SSLv3.
- **Expired or Revoked Certificates**: Certs that have expired or been added to a revocation list (CRL) are considered insecure.
- **Misconfigured Certificates**: Issues such as incorrect subject common name or mismatched certificate chain.

### Certificate Transparency

Certificate Transparency is a framework that provides a public log of issued certificates to make it easier to detect fraudulent or misissued certificates. This is an essential part of securing digital communication.

Check out Certificate Transparency logs here:
[https://certificate.transparency.dev/](https://certificate.transparency.dev/)

### Tools for Certificate Transparency and SSL Reconnaissance:

- **crt.sh**: A tool to search for SSL/TLS certificates issued for a domain. It is part of the Certificate Transparency project and helps with tracking certificate issuance.

  Example use case: 
  ```bash
  curl https://crt.sh/?q=example.com
  ```

- **Censys.io**: Another tool to search for SSL certificates across the internet.

---

# Social Media Scraping & PII

## 1. Overview

Social media scraping refers to the process of extracting data from social media platforms using automated tools or APIs. This data may include public posts, images, comments, user profiles, and, in some cases, personally identifiable information (PII).

**PII (Personally Identifiable Information)** refers to any data that can potentially identify a specific individual, such as:
- Full Name
- Email Address
- Phone Number
- IP Address
- Social Security Number
- Location Data (Geotags)

Scraping social media data can have legitimate purposes, such as research, marketing, and monitoring brand sentiment. However, gathering PII without consent can lead to legal and ethical issues.

## 2. Common Social Media Scraping Techniques

1. **API-Based Scraping**: Many social media platforms provide APIs to developers that allow for structured access to user data. For example:
   - **Twitter API**
   - **Facebook Graph API**
   - **LinkedIn API**

2. **HTML Parsing**: For sites that don't provide APIs or for public scraping, tools can be used to parse HTML and extract information. Libraries like **BeautifulSoup** and **Scrapy** in Python are commonly used.

3. **Automated Browsers**: Tools like **Selenium** can automate browsers to navigate and scrape data that is dynamically generated via JavaScript.

## 3. Tools for Social Media Scraping

### 1. **BeautifulSoup (Python)**
- A Python library for parsing HTML and XML documents. It is commonly used for web scraping projects and can handle various social media platforms.
  
  Example code:
  ```python
  from bs4 import BeautifulSoup
  import requests

  url = 'https://twitter.com/username'
  response = requests.get(url)
  soup = BeautifulSoup(response.text, 'html.parser')

  # Extracting user tweets
  tweets = soup.find_all('div', {'class': 'tweet'})
  for tweet in tweets:
      print(tweet.text)
  ```

### 2. **Selenium**
- Selenium is a browser automation tool used for scraping dynamic content from websites like social media platforms.

  Example code:
  ```python
  from selenium import webdriver

  driver = webdriver.Chrome(executable_path='/path/to/chromedriver')
  driver.get('https://twitter.com/username')

  tweets = driver.find_elements_by_class_name('tweet-text')
  for tweet in tweets:
      print(tweet.text)
  driver.quit()
  ```

### 3. **Twint (For Twitter)**
- **Twint** is an advanced Twitter scraping tool written in Python that doesn't require Twitter's API. It can scrape user data, tweets, followers, and more.

  Example command to scrape tweets:
  ```bash
  twint -u username --limit 100 --output tweets.csv
  ```

### 4. **Scrapy**
- A fast high-level web scraping and web crawling framework for Python, widely used to extract data from websites.

  Example:
  ```python
  import scrapy

  class TwitterSpider(scrapy.Spider):
      name = "twitter_spider"
      start_urls = ['https://twitter.com/username']

      def parse(self, response):
          for tweet in response.css('div.tweet'):
              yield {
                  'text': tweet.css('p.tweet-text::text').get(),
                  'date': tweet.css('span._timestamp::attr(data-time)').get(),
              }
  ```

## 4. Sites and PII Collection

### **Common Social Media Sites for Scraping**:

1. **Twitter**: Public tweets, follower lists, geotags.
2. **Facebook**: Public posts, events, and user profiles via Graph API.
3. **LinkedIn**: Public profiles, connections, job listings.
4. **Instagram**: Public posts, hashtags, comments.
5. **Reddit**: Public posts, comment threads.
6. **YouTube**: Video metadata, comments, and channel information.

### **Example Data Points Collected**:
- **Username**: Publicly available handle or name used on the platform.
- **Bio/Description**: Short descriptions or bios provided by the user.
- **Number of Followers/Following**: Useful for analytics.
- **Location**: If publicly available or geotagged.
- **Post Frequency**: Analyzing user activity.
- **Post Content**: Extracting text, images, and videos.
- **Hashtags**: Common tags associated with topics.

---

## Record Types

When using tools like `nslookup`, `dnslookup`, and `dig`, understanding the different DNS record types is crucial for performing accurate reconnaissance. Below are descriptions of common DNS record types, along with examples of how to query them using the aforementioned commands.

### 1. **NS (Name Server Record)**
The NS record specifies the authoritative name servers for a domain. These servers are responsible for providing the IP addresses of a domain's records.

#### Example Command:
```bash
dig example.com NS
```

This command will return the name servers for `example.com`.

---

### 2. **MX (Mail Exchange Record)**
The MX record specifies the mail servers responsible for receiving emails on behalf of the domain. Each MX record includes a priority value that indicates the order in which mail servers should be used.

#### Example Command:
```bash
dig example.com MX
```

This will return the mail servers for `example.com`.

---

### 3. **TXT (Text Record)**
TXT records are used to store arbitrary text in DNS records. They are often used for verification purposes or to contain security information like SPF (Sender Policy Framework) or DKIM (DomainKeys Identified Mail).

#### Example Command:
```bash
dig example.com TXT
```

This will return the text records for `example.com`, often used for domain ownership verification or email security.

---

### 4. **A (Address Record)**
The A record maps a domain name to an IPv4 address. It is one of the most common DNS records used to direct traffic to a specific server by its IP address.

#### Example Command:
```bash
dig example.com A
```

This command will return the IPv4 address associated with `example.com`.

---

### 5. **AAAA (IPv6 Address Record)**
The AAAA record maps a domain name to an IPv6 address. Like the A record, it directs traffic to the domain, but it uses the newer IPv6 protocol.

#### Example Command:
```bash
dig example.com AAAA
```

This will return the IPv6 address associated with `example.com`.

---

## Additional Resources

For more OSINT tools and techniques, you can refer to the GitHub repository: [The Art of Hacking - h4cker OSINT](https://github.com/The-Art-of-Hacking/h4cker/tree/master/osint).

This repository contains various tools and frameworks for Open Source Intelligence gathering (OSINT), including tools for:
- DNS enumeration
- WHOIS lookups
- Web crawling
- Social media scraping
- And more.

---

# Company Reputation and Security Posture

## 1. Password Dumps

Password dumps refer to large databases of leaked usernames and passwords from various breaches. Searching for such leaked credentials can help organizations assess the risk of credential stuffing attacks and identify compromised accounts. Various tools help search for such data across multiple dumps.

### 1.1 **Implementation of h8mail**

**h8mail** is an email OSINT and breach hunting tool that allows you to find compromised accounts in breached databases. It supports searching for leaked credentials in multiple breach databases.

#### Installation:
```bash
pip install h8mail
```

#### Example Usage:
```bash
h8mail -t target_email@example.com -bc your_api_key
```

This command will search for breaches associated with `target_email@example.com` using your breach API key.

### 1.2 Additional Tools for Breach Data Dumps

1. **[WhatBreach](https://github.com/Ekultek/WhatBreach)**:
   - A tool to search for data breaches and passwords.
   - Usage:
     ```bash
     python whatbreach.py -u example.com
     ```

2. **[LeakLooker](https://github.com/woj-ciech/LeakLooker)**:
   - Scans for publicly available databases and files that have been exposed.
   - Supports searching for misconfigured databases.

3. **[Buster](https://github.com/sham00n/buster)**:
   - A tool to search for email addresses and credentials in online data breaches.

4. **[Scavenger](https://github.com/rndinfosecguy/Scavenger)**:
   - Collects information about exposed assets like databases or cloud storage.

5. **[PwnDB](https://github.com/davidtavarez/pwndb)**:
   - Searches for leaked credentials on Pastebin-like services and hacked databases.
   - Usage:
     ```bash
     python pwndb.py -q target_email@example.com
     ```

### 1.3 Popular Breach Check Websites

- **[HaveIBeenPwned](https://haveibeenpwned.com/)**: A well-known site to check if an email has been part of a breach.
- **[F-Secure](https://www.f-secure.com/)**: Provides security products and breach detection tools.
- **[HackNotice](https://www.hacknotice.com/)**: Offers breach alert services.
- **[BreachDirectory](https://breachdirectory.com/)**: A search engine for breached databases.
- **[Keeper Security](https://www.keepersecurity.com/)**: A password management tool with breach detection features.

---

## 2. File Metadata

File metadata contains hidden information that can give insights into who created the file, when it was created, device details, and more. Extracting metadata from files can reveal sensitive information, which may pose a security risk.

### 2.1 **Implementation of ExifTool**

**ExifTool** is a powerful tool for reading, writing, and editing metadata in various file formats. It supports a wide variety of file types such as documents, images, audio, video, and more.

#### Installation:
```bash
sudo apt install exiftool
```

#### Example Usage:

- **Extract metadata from a file**:
    ```bash
    exiftool file.pdf
    ```

- **Extract specific metadata (e.g., author)**:
    ```bash
    exiftool -Author file.docx
    ```

- **Remove metadata**:
    ```bash
    exiftool -all= file.jpg
    ```

#### Formats Supported:
- **Documents**: PDF, DOCX, PPTX, etc.
- **Images**: JPEG, PNG, GIF, TIFF, etc.
- **Audio/Video**: MP3, MP4, WAV, AVI, etc.
- **Graphics**: SVG, EPS, AI
- **Archives**: ZIP, RAR, TAR, etc.

---

## 3. Strategic Search Engine Analysis/Enumeration

Search engine analysis can provide valuable information by using specific queries to uncover hidden or sensitive data exposed online. Google Dorking is a technique used to find such information by using advanced search operators.

### 3.1 Google Dorking

Google Dorking involves the use of specific search queries to uncover sensitive data indexed by search engines. It's a powerful method for finding publicly exposed data like passwords, configuration files, and confidential documents.

#### Common Google Dorks:
```bash
intitle:"index of" passwd
inurl:"login.asp" "admin"
site:example.com filetype:pdf confidential
inurl:"wp-admin"
intitle:"sensitive"
```

### 3.2 Google Hacking Database (GHDB)

**[Google Hacking Database (GHDB)](https://www.exploit-db.com/google-hacking-database)** is a repository of Google search queries (dorks) used by security professionals to find vulnerabilities and sensitive information.

---

## 4. Website Archiving/Caching

Website archiving or caching allows you to view the historical versions of a website, which can be useful for digital forensics, security research, or uncovering old vulnerabilities.

### 4.1 Wayback Machine

**[Wayback Machine](https://archive.org/web)** by the Internet Archive provides access to archived web pages, enabling users to view websites as they appeared in the past.

#### Example Usage:
1. Visit: https://archive.org/web
2. Enter the target website URL.
3. Browse through historical snapshots of the website.

---

## 5. Public Source Code Repositories

Source code repositories such as GitHub, GitLab, and Bitbucket often contain valuable information, including misconfigured files, exposed API keys, and credentials. Regular audits of public repositories are crucial for maintaining a strong security posture.

#### Popular Repositories:
- **[GitHub](https://github.com/)**: Largest repository hosting service.
- **[GitLab](https://gitlab.com/)**: Provides built-in CI/CD features for DevOps.
- **[Bitbucket](https://bitbucket.org/)**: Offers Git repository hosting with integration to Jira.

#### Strategic Auditing of Repositories:
Search for sensitive data (API keys, passwords, config files) in repositories:
```bash
git log -p | grep -i "password"
```

Ensure `.gitignore` files are properly configured to avoid accidental exposure of sensitive data.

---

## Conclusion

By utilizing these tools, you can gather a wealth of information while remaining completely invisible to the target, forming the foundation for more focused active testing.

---


This version covers key tools for passive reconnaissance, focusing on **Kali Linux** usage and including practical examples and detailed steps for each tool. It also integrates API implementation examples and tool documentation links for further exploration.
