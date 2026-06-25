# ShadowProbe 

**ShadowProbe** is an advanced Python wrapper for the Nmap engine. It automates network scanning, handles privilege-based OS constraints, and transforms raw Nmap data into clean, structured JSON and readable text reports. 

Designed for cybersecurity analysts and engineers who need to quickly ingest scan data into other tools or databases.

##  Features
* **Smart Input Validation:** Safely parses single IPs, hostnames, CIDR subnets, and custom port ranges.
* **Privilege Awareness:** Automatically detects root/admin privileges and adjusts scan types (SYN vs. TCP-Connect) to prevent crashes.
* **Threaded Execution:** Runs scans in a background daemon thread with a live terminal spinner to prevent blocking UX.
* **Data Transformation:** Converts messy raw socket data into highly structured JSON payloads.
* **Defensive File Handling:** Sanitizes all user-provided filepaths to prevent directory traversal or invalid characters.

##  Installation

**Prerequisites:** You must have the core `nmap` system binary installed on your machine and added to your system PATH.
* Linux: `sudo apt install nmap`
* Mac: `brew install nmap`
* Windows: Download from [nmap.org](https://nmap.org/download.html)

Clone the repository and install the Python dependencies:

```bash
git clone [https://github.com/Testosterouna/ShadowProbe.git](https://github.com/Testosterouna/ShadowProbe.git)
cd ShadowProbe
pip install -r requirements.txt

## 🚀 Usage

ShadowProbe is designed to be flexible, supporting both quick unprivileged scans and deep, root-level fingerprinting. 

**Note on Privileges:** Advanced Nmap features like OS Fingerprinting (`-O`) and Stealth SYN Scans (`-sS`) require raw socket access. If you run ShadowProbe as a standard user, you **must** append the `--tcp-connect` flag, and OS detection will be automatically disabled to prevent crashes.

### Command-Line Arguments

| Flag | Long Name | Description | Default |
| :--- | :--- | :--- | :--- |
| `-t` | `--target` | Target IP, hostname, CIDR subnet, or comma-separated list. | *Required* (or `-f`) |
| `-f` | `--target-file` | Path to a text file containing a list of targets. | *Required* (or `-t`) |
| `-r` | `--range` | Port range (e.g., `1-1000`, `22,80,443`, `1-65535`). | `1-1000` |
| `-sC` | `--scripts` | Execute default Nmap safe discovery and vulnerability scripts. | `False` |
| `-u` | `--udp` | Enable UDP port scanning alongside TCP. | `False` |
| `--tcp-connect` | N/A | Force a TCP Connect scan (`-sT`). Use this if you lack root/admin rights. | `False` |
| `--no-os` | N/A | Disable OS fingerprinting (`-O`) to speed up the scan. | `False` |
| `--no-ping` | N/A | Skip host discovery (`-Pn`). Treat all hosts as online (useful for bypassing firewalls). | `False` |
| `-T` | `--timing` | Nmap timing template (`1` to `5`). Higher is faster but noisier. | `4` |
| `--no-version` | N/A | Disable service version detection (`-sV`) for a faster scan. | `False` |
| `-o` | `--output` | Custom base file path for reports (e.g., `/tmp/scans/results`). | Auto-generated |
| `--json` | N/A | Export a structured `.json` data payload alongside the text report. | `False` |

---

### 📖 Practical Examples

**1. Basic Subnet Discovery (Non-Root)**
Quickly scan a local subnet without administrative privileges, disabling OS detection and forcing a TCP connection.
```bash
python3 shadowprobe.py -t 192.168.1.0/24 --tcp-connect

**2. Deep Target Reconnaissance (Root/Admin)
Scan specific web and management ports, run default scripts, attempt OS fingerprinting, and output the data to JSON for external ingestion.
sudo python3 shadowprobe.py -t scanme.nmap.org -r 22,80,443,8080 -sC --json
