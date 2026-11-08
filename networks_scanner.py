import nmap
import requests
import socket
import urllib3
from datetime import datetime

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Common UDP ports
UDP_PORTS = "53,67,68,69,123,137,138,161,162,500,514,520,631,1900,4500"


# Display only open ports
def display_open_ports(host, scanner):

    data = scanner[host]
    found = False

    for protocol in data.all_protocols():

        for port in sorted(data[protocol].keys()):

            service = data[protocol][port]

            if service["state"] == "open":

                found = True

                print(
                    f"  {protocol.upper()} Port: {port} | "
                    f"Service: {service.get('name', 'Unknown')} | "
                    f"Product: {service.get('product', 'Unknown')} | "
                    f"Version: {service.get('version', 'Unknown')}"
                )

    if not found:
        print("  No confirmed open ports found.")


# Detailed single IP scan
def detailed_scan(target):

    scanner = nmap.PortScanner()

    print("\nStarting detailed scan:", target)

    scanner.scan(
        hosts=target,
        ports="T:1-1000,U:"+UDP_PORTS,
        arguments="-sS -sU -sV -T4 --reason"
    )

    if target not in scanner.all_hosts():
        print("Host not found or not responding.")
        return

    data = scanner[target]

    print("\n========== DEVICE INFORMATION ==========")
    print("IP Address:", target)
    print("Hostname:", data.hostname() or "Unknown")

    addresses = data.get("addresses", {})
    print("MAC Address:", addresses.get("mac", "Unknown"))

    vendor = data.get("vendor", {})
    print("Vendor:", ", ".join(vendor.values()) if vendor else "Unknown")

    if data.get("osmatch"):
        print("Operating System:", data["osmatch"][0]["name"])
    else:
        print("Operating System: Unknown")

    print("\n========== OPEN PORTS ==========")
    display_open_ports(target, scanner)


# Network range scan

def network_scan(target):

    scanner = nmap.PortScanner()

    print("\nDiscovering Network Devices...")

    scanner.scan(hosts=target, arguments="-sn -T4")

    hosts = scanner.all_hosts()

    print("\nTotal Devices Found:", len(hosts))

    if not hosts:
        print("No devices found.")
        return

    for index, host in enumerate(hosts, start=1):

        print("\n====================================")
        print(f"DEVICE {index}/{len(hosts)}")
        print("====================================")

        data = scanner[host]

        # Hostname
        print("IP Address:", host)
        print("Hostname:", data.hostname() or "Unknown")

        # MAC Address
        addresses = data.get("addresses", {})
        print("MAC Address:", addresses.get("mac", "Unknown"))

        # Vendor
        vendor = data.get("vendor", {})
        print("Vendor:", ", ".join(vendor.values()) if vendor else "Unknown")

        print("\nScanning Open Ports...")

        device_scanner = nmap.PortScanner()

        try:

            device_scanner.scan(
                hosts=host,
                ports="T:1-1000,U:53,123,161",
                arguments="-sS -sU -T4 --reason"
            )

            if host in device_scanner.all_hosts():
                display_open_ports(host, device_scanner)
            else:
                print("Host did not respond.")

        except nmap.PortScannerError as e:
            print("Scan Error:", e)

        print("\nFinished:", host)


# Main program
print("\n========== NETWORK VULNERABILITY SCANNER ==========")
print("1. Scan Network Range")
print("2. Detailed Single IP Scan")

choice = input("\nChoose scan mode (1 or 2): ")

target = input("Enter IP address or Network Range: ")

start_time = datetime.now()

try:

    # Validate IP or network range
    if "/" not in target:
        socket.gethostbyname(target)

    if choice == "1":

        network_scan(target)

    elif choice == "2":

        detailed_scan(target)

    else:

        print("Invalid choice.")

except (nmap.PortScannerError, socket.gaierror, ValueError) as e:

    print("Error:", e)

print("\nScan Started:", start_time)
print("Scan Completed:", datetime.now())
print("\n========== SCAN COMPLETED ==========")
