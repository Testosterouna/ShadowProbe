# ShadowProbe 🕵️‍♂️

**ShadowProbe** is an advanced Python wrapper for the Nmap engine. It automates network scanning, handles privilege-based OS constraints, and transforms raw Nmap data into clean, structured JSON and readable text reports. 

Designed for cybersecurity analysts and engineers who need to quickly ingest scan data into other tools or databases.

## ✨ Features
* **Smart Input Validation:** Safely parses single IPs, hostnames, CIDR subnets, and custom port ranges.
* **Privilege Awareness:** Automatically detects root/admin privileges and adjusts scan types (SYN vs. TCP-Connect) to prevent crashes.
* **Threaded Execution:** Runs scans in a background daemon thread with a live terminal spinner to prevent blocking UX.
* **Data Transformation:** Converts messy raw socket data into highly structured JSON payloads.
* **Defensive File Handling:** Sanitizes all user-provided filepaths to prevent directory traversal or invalid characters.

## ⚙️ Installation

**Prerequisites:** You must have the core `nmap` system binary installed on your machine and added to your system PATH.
* Linux: `sudo apt install nmap`
* Mac: `brew install nmap`
* Windows: Download from [nmap.org](https://nmap.org/download.html)

Clone the repository and install the Python dependencies:

```bash
git clone [https://github.com/Testosterouna/ShadowProbe.git](https://github.com/Testosterouna/ShadowProbe.git)
cd ShadowProbe
pip install -r requirements.txt
