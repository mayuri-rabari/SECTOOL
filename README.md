🛡️ SECTOOL – Cybersecurity CLI Toolkit
A fast, modular, no-dependency security toolkit for pentesters & analysts.
<p align="center"> <img src="https://img.shields.io/badge/Language-Python-blue?style=for-the-badge"> <img src="https://img.shields.io/badge/Platform-Windows%20%7C%20Linux-red?style=for-the-badge"> <img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge"> <img src="https://img.shields.io/badge/Version-1.0.0-purple?style=for-the-badge"> </p>
🌟 Overview

SECTOOL is a multi-purpose command-line security toolkit that combines essential pentesting and analysis utilities:

⚡ Fast multi-threaded Port Scanner

📡 Intelligent Banner Grabber (HTTP/HTTPS + TLS details)

🌐 Deep URL Security Analyzer (SSL, WHOIS, headers)

🔐 Smart Hash Analyzer (auto-detect + reverse lookup)

🧠 Real-time Process Monitor (behavioral alerts)

Zero bloat. No Nmap dependency. Works on Windows, Linux, Kali, Ubuntu.

📦 Installation
1. Clone Repository
git clone https://github.com/yourusername/sectool.git
cd sectool

2. Create Virtual Environment
Windows
python -m venv .venv
.\.venv\Scripts\Activate.ps1

Linux / Kali
python3 -m venv .venv
source .venv/bin/activate

3. Install Tool
pip install -e .

4. Verify Install
sectool --help

🧭 Command Overview
Command	Description
portscan	Scan open ports on an IP or domain
bannergrab	Extract HTTP/HTTPS banners + TLS info
urlcheck	Full URL analysis (SSL, WHOIS, status)
hashdb	Identify & reverse-lookup hashes
processmon	Real-time suspicious process monitoring
🔥 1. PORT SCANNER
Basic Scan
sectool portscan --host 127.0.0.1 --ports 1-100

Scan specific ports
sectool portscan --host example.com --ports 80,443,3306

Fast multi-threaded mode
sectool portscan --host 192.168.1.1 --ports 1-1500 --fast

Scan & grab banners
sectool portscan --host example.com --ports 80,443 --banner

📡 2. BANNER GRABBER
Auto-detect HTTP/HTTPS
sectool bannergrab --url google.com

HTTPS + TLS certificate details
sectool bannergrab --url https://amazon.com

Custom port
sectool bannergrab --url example.com:8080

Output includes:

Server type

HTTP headers

TLS version

Cipher suite

Certificate issuer

Validity dates

🌐 3. URL SECURITY CHECK
Run full analysis
sectool urlcheck --url https://amazon.com

Report includes:

HTTP status

Server headers

SSL certificate details

WHOIS domain information

Risk indicators

No VirusTotal dependency

🔐 4. HASH ANALYZER

Supported algorithms:

Type	Detection	Reverse
MD5	✔	✔
SHA1	✔	✔
SHA224	✔	✔
SHA256	✔	✔
SHA384	✔	✔
SHA512	✔	✔
NTLM	✔	✖
BCrypt	✔	✖
Argon2	✔	✖
Usage
sectool hashdb --hash 5f4dcc3b5aa765d61d8327deb882cf99

Example output
[*] Hash Type: MD5
[*] Reverse Lookup: password

🧠 5. PROCESS MONITOR

Real-time detection of:

Suspicious process names

New process creation

Terminated processes

High CPU spikes

High RAM usage

Active network connections

Start monitoring
sectool processmon

🆘 Help Menu
Global help
sectool --help

Command-specific help
sectool portscan --help
sectool bannergrab --help
sectool urlcheck --help
sectool hashdb --help
sectool processmon --help
