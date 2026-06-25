import sys
import argparse
import ipaddress
import json
import shutil
import re
import threading
import time
from pathlib import Path
from urllib.parse import urlparse
from datetime import datetime

# --- Dependency & System Checks ---
try:
    import nmap # pyright: ignore[reportMissingModuleSource]
except ImportError:
    print("[-] Error: python-nmap is not installed.")
    print("    Install it with: pip3 install python-nmap")
    sys.exit(1)

if not shutil.which("nmap"):
    print("[-] Error: 'nmap' system binary is not installed or not in your PATH.")
    print("    Install it (e.g., 'sudo apt install nmap' or download from nmap.org).")
    sys.exit(1)


def normalize_target(target):
    """Normalize a single target string by stripping URL schemes and trailing slashes."""
    if target.startswith(("http://", "https://")):
        parsed = urlparse(target)
        target = parsed.hostname or target
    return target.rstrip("/")


def validate_target(target):
    """Validate IP address, CIDR network, or resolvable hostname format."""
    # 1. Check if valid IPv4/IPv6 address
    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        pass

    # 2. Check if valid CIDR network
    try:
        ipaddress.ip_network(target, strict=False)
        return True
    except ValueError:
        pass

    # 3. Fast regex hostname validation to avoid blocking DNS resolution.
    # Allow internal hostnames and local names, including underscores.
    label_regex = r'(?:[A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9_-]{0,61}[A-Za-z0-9])'
    hostname_regex = re.compile(rf'^{label_regex}(?:\.{label_regex})*$')

    if hostname_regex.match(target):
        return True

    return False


def load_targets_from_file(path):
    """Read targets from a file, failing fast if the file is missing."""
    file_path = Path(path)
    
    if not file_path.is_file():
        raise FileNotFoundError(f"Target file '{path}' not found or is inaccessible.")

    targets = []
    with file_path.open('r', encoding='utf-8') as target_file:
        for line in target_file:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            values = [item.strip() for item in line.split(',') if item.strip()]
            targets.extend(values)
    return targets


def parse_targets(target_input):
    """Parse comma-separated targets into a clean list."""
    return [normalize_target(token) for token in target_input.split(',') if normalize_target(token)]


def validate_ports(port_input):
    """
    Validate port input. Allows single ports, ranges, and comma-separated lists.
    Examples: '80', '1-1000', '22,80,443', '22,80-100'
    """
    if not port_input:
        return False

    tokens = port_input.split(',')
    for token in tokens:
        if not token:
            return False
        if '-' in token:
            try:
                start, end = map(int, token.split('-'))
            except ValueError:
                return False
            if start < 1 or end < 1 or start > 65535 or end > 65535 or start > end:
                return False
        else:
            try:
                value = int(token)
            except ValueError:
                return False
            if value < 1 or value > 65535:
                return False

    return True


def sanitize_output_path(filepath):
    """Sanitize user-provided output path using pathlib."""
    p = Path(filepath)
    
    # Extract base name without known extensions
    basename = p.stem if p.suffix.lower() in ['.txt', '.json'] else p.name
        
    # Sanitize the filename
    basename = re.sub(r'[<>:"/\\|?*\x00-\x1f]+', '_', basename).strip()
    basename = basename or "scan_output"
    
    # Re-join and ensure parent directory exists
    out_dir = p.parent
    if out_dir != Path('.'):
        out_dir.mkdir(parents=True, exist_ok=True)
        return str(out_dir / basename)
        
    return basename


def check_privileges():
    """Cross-platform check for root/administrator privileges."""
    try:
        # Unix/Linux
        import os
        return os.geteuid() == 0
    except AttributeError:
        # Windows
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except (OSError, AttributeError):
            return False


def print_banner(targets, port_range, scan_args):
    print("=" * 60)
    print(" SHADOWPROBE ADVANCED SCANNER ENGINE ".center(60, "="))
    print("=" * 60)
    print(f"[*] Target(s):  {', '.join(targets)}")
    print(f"[*] Ports:      {port_range}")
    print(f"[*] Engine:     Nmap via python-nmap")
    print(f"[*] Args:       {scan_args}")
    print(f"[*] Started:    {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 60 + "\n")


def build_nmap_args(port_range, enable_scripts, enable_udp, scan_tcp_connect, enable_os, no_ping, timing, enable_version=True):
    args = []
    args.append("-sT" if scan_tcp_connect else "-sS")
    if enable_udp: args.append("-sU")
    if enable_version: args.append("-sV")
    args.extend([f"-T{timing}", f"-p {port_range}"])
    if enable_os: args.append("-O")
    if enable_scripts: args.append("-sC")
    if no_ping: args.append("-Pn")
    return " ".join(args)


def _run_nmap_background(nm, target_string, scan_args, timeout=None):
    """Run Nmap in a background thread while the main thread updates status."""
    result = {"error": None}

    def worker():
        try:
            nm.scan(hosts=target_string, arguments=scan_args)
        except nmap.PortScannerError as e:
            result["error"] = e

    thread = threading.Thread(target=worker, daemon=True)
    thread.start()

    spinner = ['|', '/', '-', '\\']
    idx = 0
    start_time = datetime.now()

    while thread.is_alive():
        elapsed = datetime.now() - start_time
        mins, secs = divmod(int(elapsed.total_seconds()), 60)
        sys.stdout.write(
            f"\r[*] Scan in progress... {spinner[idx % len(spinner)]} "
            f"elapsed {mins:02d}:{secs:02d}"
        )
        sys.stdout.flush()
        idx += 1
        time.sleep(0.15)

    thread.join(timeout)
    sys.stdout.write("\r" + " " * 80 + "\r")
    sys.stdout.flush()

    if result["error"]:
        raise result["error"]


def execute_scan(targets, port_range, enable_scripts, enable_udp, scan_tcp_connect, enable_os, no_ping, timing, enable_version):
    """Handle Nmap execution and return parsed host objects."""
    nm = nmap.PortScanner()
    scan_args = build_nmap_args(port_range, enable_scripts, enable_udp, scan_tcp_connect, enable_os, no_ping, timing, enable_version)

    print_banner(targets, port_range, scan_args)
    print("[*] Scan is running. This may take a minute or more depending on the host and options...\n")

    target_string = ",".join(targets)
    try:
        _run_nmap_background(nm, target_string, scan_args)
    except nmap.PortScannerError as e:
        raise RuntimeError(
            f"Nmap Engine Error: {e}\n"
            f"[!] CRITICAL: OS Fingerprinting and SYN scans require raw sockets (Root/Admin).\n"
            f"[!] Run with sudo/admin or use --tcp-connect."
        )

    scanned_hosts = nm.all_hosts()
    if not scanned_hosts:
        msg = (
            "[!] Even with '--no-ping' (-Pn), Nmap returned no open ports or host data."
            if no_ping else
            "[?] Try adding '--no-ping' to skip host discovery (-Pn)."
        )
        raise RuntimeError(f"All targets appear to be DOWN or blocking probes.\n{msg}")

    return nm, scanned_hosts


def parse_scan_data(nm, scanned_hosts, targets, enable_udp):
    """Process raw Nmap output into structured JSON and text report lines."""
    scan_results = {
        "targets": targets,
        "scan_time": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        "host_count": len(scanned_hosts),
        "hosts": []
    }

    report_lines = [
        f"=== SHADOWPROBE REPORT: {', '.join(targets)} ===",
        f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
    ]

    open_tcp_count = 0
    open_udp_count = 0

    for host in sorted(scanned_hosts):
        host_data = nm[host]
        host_state = host_data.state() if host_data else "unknown"
        mac_address = host_data.get('addresses', {}).get('mac', 'Unknown')

        os_match = "Unknown"
        os_accuracy = "0"
        if 'osmatch' in host_data and host_data['osmatch']:
            os_match = host_data['osmatch'][0].get('name', 'Unknown')
            os_accuracy = str(host_data['osmatch'][0].get('accuracy', '0'))

        try:
            os_confidence = int(float(os_accuracy))
        except (TypeError, ValueError):
            os_confidence = 0

        host_entry = {
            "host": host,
            "state": host_state.upper(),
            "mac_address": mac_address,
            "os_guess": {"name": os_match, "confidence": os_confidence},
            "ports": {"tcp": [], "udp": []}
        }

        report_lines.append(f"\n=== HOST: {host} ===")
        report_lines.append(f"State:       {host_state.upper()}")
        report_lines.append(f"MAC Address: {mac_address}")
        report_lines.append(f"OS Match:    {os_match} ({os_accuracy}% Confidence)\n")
        report_lines.append("--- OPEN PORTS & VERSIONS ---")

        if 'tcp' in host_data:
            report_lines.append("\n[TCP PORTS]")
            for port in sorted(host_data['tcp'].keys()):
                port_data = host_data['tcp'][port]
                if port_data.get('state') == 'open':
                    open_tcp_count += 1
                    name = port_data.get('name', 'unknown')

                    product = port_data.get('product', '')
                    version = port_data.get('version', '')
                    extrainfo = port_data.get('extrainfo', '')
                    version_string = " ".join(filter(None, [product, version, extrainfo])).strip()
                    if not version_string:
                        version_string = "Version Unknown"

                    report_lines.append(f"[{port:5d}/tcp] {name:10s} | {version_string}")

                    scripts_dict = {}
                    if 'script' in port_data:
                        for script_name, script_output in port_data['script'].items():
                            output_lines = str(script_output).splitlines()
                            first_line = output_lines[0] if output_lines else ""
                            report_lines.append(f"    └─ [{script_name}] {first_line[:80]}...")
                            scripts_dict[script_name] = output_lines

                    host_entry["ports"]["tcp"].append({
                        "port": port,
                        "protocol": "tcp",
                        "service": name,
                        "version": version_string,
                        "scripts": scripts_dict
                    })

        if enable_udp and 'udp' in host_data:
            report_lines.append("\n[UDP PORTS]")
            for port in sorted(host_data['udp'].keys()):
                port_data = host_data['udp'][port]
                if port_data.get('state') == 'open':
                    open_udp_count += 1
                    name = port_data.get('name', 'unknown')
                    report_lines.append(f"[{port:5d}/udp] {name}")
                    host_entry["ports"]["udp"].append({"port": port, "protocol": "udp", "service": name})

        if not host_entry["ports"]["tcp"] and not host_entry["ports"]["udp"]:
            report_lines.append("No open ports found.")

        scan_results["hosts"].append(host_entry)

    report_lines.append(f"\n[*] Total Open TCP Ports: {open_tcp_count}")
    if enable_udp:
        report_lines.append(f"[*] Total Open UDP Ports: {open_udp_count}")
    report_lines.append(f"[*] Scan Completed:   {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    return scan_results, report_lines


def save_reports(report_lines, scan_results, custom_output, export_json, targets):
    """Save text and optional JSON reports to disk."""
    if custom_output:
        out_path = Path(custom_output)
        out_dir = out_path.parent
        out_dir.mkdir(parents=True, exist_ok=True)

        safe_name = re.sub(r'[<>:"/\\|?*\x00-\x1f]+', '_', out_path.name).strip()
        if not safe_name:
            safe_name = "scan_output"

        base_path = out_dir / safe_name
        if out_path.suffix.lower() in ['.txt', '.json']:
            base_path = out_dir / out_path.stem
    else:
        safe_targets = '_'.join([t.replace('.', '_').replace('/', '_') for t in targets])
        base_path = Path(f"scan_{safe_targets}_{datetime.now().strftime('%Y%m%d_%H%M')}")

    txt_file = base_path.with_suffix('.txt')
    try:
        with txt_file.open('w', encoding='utf-8') as f:
            f.write("\n".join(report_lines) + "\n")
        print(f"\n[✓] Text report saved to: {txt_file}")
    except IOError as e:
        print(f"\n[✗] Error saving text file: {e}")

    if export_json:
        json_file = base_path.with_suffix('.json')
        try:
            with json_file.open('w', encoding='utf-8') as jf:
                json.dump(scan_results, jf, indent=4)
            print(f"[✓] JSON data exported to: {json_file}")
        except IOError as e:
            print(f"[✗] Error saving JSON file: {e}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="ShadowProbe: Advanced Nmap Integration Engine",
        epilog="Example: sudo python3 shadowprobe.py -t scanme.nmap.org -r 22,80,443 -sC --json"
    )
    parser.add_argument("-t", "--target", help="Target IP address, hostname, CIDR subnet, or comma-separated list of targets")
    parser.add_argument("-f", "--target-file", help="File containing targets, one per line or comma-separated")
    parser.add_argument("-r", "--range", default="1-1000", help="Port range (e.g., 1-65535 or 22,80,443)")
    parser.add_argument("-sC", "--scripts", action="store_true", help="Run default Nmap scripts")
    parser.add_argument("-u", "--udp", action="store_true", help="Enable UDP scanning")
    parser.add_argument("--tcp-connect", action="store_true", help="Use TCP connect scan (-sT) instead of SYN scan (-sS). Useful if not root.")
    parser.add_argument("--no-os", action="store_true", help="Disable OS detection (-O)")
    parser.add_argument("--no-ping", action="store_true", help="Skip host discovery with -Pn")
    parser.add_argument("-T", "--timing", type=int, choices=range(1, 6), default=4, help="Nmap timing template (1-5). Default is 4.")
    parser.add_argument("-o", "--output", help="Custom base output filepath (e.g., /tmp/results/my_scan)")
    parser.add_argument("--json", dest="export_json", action="store_true", help="Export a structured .json file alongside the text report")
    parser.add_argument("--no-version", dest="version_detect", action="store_false", help="Disable service version detection (-sV)")

    args = parser.parse_args()

    targets = []
    if args.target:
        targets.extend(parse_targets(args.target))
    if args.target_file:
        targets.extend(load_targets_from_file(args.target_file))

    targets = [normalize_target(target) for target in targets if target]
    targets = list(dict.fromkeys(targets))

    if not targets:
        print("[-] No targets provided. Use --target or --target-file.")
        sys.exit(1)

    for target_item in targets:
        if not validate_target(target_item):
            print(f"[-] Invalid target: '{target_item}'. Must be a valid IP, CIDR subnet, or resolvable hostname.")
            sys.exit(1)

    if not validate_ports(args.range):
        print(f"[-] Invalid port format: {args.range}")
        print("    Use format: start-end (1-1000) or comma-separated (22,80,443)")
        sys.exit(1)

    is_admin = check_privileges()
    if not is_admin and not args.tcp_connect:
        print("[!] ERROR: Non-root/admin users must use --tcp-connect for scanning.")
        print("    Run as administrator/root or add --tcp-connect to use TCP connect scan.")
        sys.exit(1)

    enable_os = not args.no_os
    if not is_admin and enable_os:
        print("[!] WARNING: OS detection (-O) requires root/admin privileges.")
        print("    Disabling OS detection for this run.\n")
        enable_os = False

    try:
        nm, scanned_hosts = execute_scan(
            targets,
            args.range,
            args.scripts,
            args.udp,
            args.tcp_connect,
            enable_os,
            args.no_ping,
            args.timing,
            args.version_detect
        )

        scan_results, report_lines = parse_scan_data(nm, scanned_hosts, targets, args.udp)
        print("\n" + "\n".join(report_lines))
        save_reports(report_lines, scan_results, args.output, args.export_json, targets)
    except RuntimeError as e:
        print(f"[-] {e}")
        sys.exit(1)
