# 🛡️ Net Analyzer Pro (Security Edition)

![Version](https://img.shields.io/badge/version-3.2.1-blue?style=for-the-badge)
![Format](https://img.shields.io/badge/Format-Raw%20.py%20Script-yellow?style=for-the-badge)
![Platform](https://img.shields.io/badge/Built%20On-Linux-orange?style=for-the-badge)
![Category](https://img.shields.io/badge/Category-Network%20Security-red?style=for-the-badge)

**Net Analyzer Pro** is a raw, open-source network security and analysis tool built natively on **Linux**. It is designed for system administrators, developers, and security enthusiasts to audit and monitor *their own* network environments.

---

## ⚠️ CRITICAL USAGE WARNING (READ FIRST)

> **⛔ DO NOT USE FEATURES YOU DO NOT UNDERSTAND.**
>
> This tool contains powerful networking capabilities (Packet Sniffing, Port Scanning, Nmap Integration) that interact directly with network protocols.
>
> 1.  **AUTHORIZED USE ONLY:** You must **only** use this tool on networks you own (your home Wi-Fi) or have explicit written permission to test.
> 2.  **LEGAL RISK:** Scanning networks, sniffing packets, or probing ports on unauthorized networks (e.g., Coffee Shops, Corporate Offices, Government sites) is **ILLEGAL** in many jurisdictions and is considered a cybercrime.
> 3.  **NO ILLEGAL HACKING:** This tool is strictly for **Educational** and **Defensive Security** purposes.
>
> **The developer (PSBDx) assumes NO liability for misuse of this software.**

---

## 🐧 Why Linux Only?

This tool was built and optimized on **Zorin OS/Linux**.
Network security requires "Low-Level" access to hardware interfaces (Raw Sockets). Linux allows this control, whereas Windows and macOS often block these actions for security reasons.

**Compatibility:**
* ✅ **Native:** Chrome OS, Chromebooks (Crostini), Ubuntu, Kali Linux, Windows (WSL), Zorin OS.
* ❌ **Windows/Mac:** Not supported (requires Raw Socket access).

---

## 📂 Source Code Distribution

To ensure **100% Transparency** and security, we do not distribute executable files (`.exe`, `.dmg`).
You get the **Raw Python Code (`.py`)**. You can read every line to verify that there are no backdoors or hidden trackers before running it.

---

## ⚡ Features & Capabilities

* **📊 Live Traffic Analysis:** Real-time monitoring of data packets entering/leaving the interface.
* **📡 Subnet Reconnaissance:** Uses **Nmap** to map the local network, finding connected devices, IP addresses, and MAC vendors.
* **🕵️ Packet Sniffing (Matrix Mode):** Captures live headers (TCP/UDP/ICMP). *Warning: This feature intercepts real-time data.*
* **🌐 Domain Intelligence:** Performs WHOIS lookups to gather ownership data on domains.
* **🛡️ Self-Audit:** Check your own ISP visibility and public IP exposure.

---

## ⚙️ Setup & Execution

### Step 1: Download the Script
Download the `net_analyzer_pro.py` file to your Linux machine.

### Step 2: Install System Tools
You need `nmap` for scanning and `libxcb` for the GUI:
```bash
sudo apt update
sudo apt install nmap libxcb-cursor0 -y
