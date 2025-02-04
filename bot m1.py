import os
import subprocess

def run_nmap_scan(target):
    print(f"Running Nmap scan on {target}...")
    result = subprocess.run(["nmap", "-A", target], capture_output=True, text=True)
    print(result.stdout)


def run_whois_lookup(domain):
    print(f"Performing WHOIS lookup for {domain}...")
    result = subprocess.run(["whois", domain], capture_output=True, text=True)
    print(result.stdout)


def run_masscan(target):
    print(f"Running Masscan on {target}...")
    result = subprocess.run(["masscan", "-p1-65535", target], capture_output=True, text=True)
    print(result.stdout)


def capture_packets(interface, duration=10):
    print(f"Capturing network packets on {interface} for {duration} seconds...")
    subprocess.run(["sudo", "tcpdump", "-i", interface, "-w", "capture.pcap", "-G", str(duration), "-W", "1"])
    print("Packet capture completed. Saved as capture.pcap")


def run_sqlmap(target_url):
    print(f"Running SQL Injection test on {target_url}...")
    result = subprocess.run(["sqlmap", "-u", target_url, "--batch"], capture_output=True, text=True)
    print(result.stdout)


def perform_metasploit_scan(target):
    print(f"Running Metasploit scan on {target}...")
    subprocess.run(["msfconsole", "-q", "-x", f"use auxiliary/scanner/portscan/tcp; set RHOSTS {target}; run; exit"], capture_output=True, text=True)
    print("Metasploit scan completed.")


def run_wireshark(interface, duration=10):
    print(f"Starting Wireshark capture on {interface} for {duration} seconds...")
    subprocess.run(["sudo", "tshark", "-i", interface, "-a", f"duration:{duration}", "-w", "wireshark_capture.pcap"])
    print("Wireshark capture saved.")


def run_ddos_attack(target_ip, duration=10):
    print(f"Simulating DDoS attack on {target_ip} for {duration} seconds...")
    subprocess.run(["hping3", "--flood", "--rand-source", "-p", "80", target_ip], capture_output=True, text=True)
    print("DDoS simulation completed.")


def main():
    while True:
        print("\nSecurity Practical Bot")
        print("1. Run Nmap Scan")
        print("2. Perform WHOIS Lookup")
        print("3. Run Masscan")
        print("4. Capture Network Packets")
        print("5. Perform SQL Injection Test")
        print("6. Perform Metasploit Scan")
        print("7. Run Wireshark Capture")
        print("8. Simulate DDoS Attack")
        print("9. Exit")
        choice = input("Select an option: ")

        if choice == "1":
            target = input("Enter target IP or domain: ")
            run_nmap_scan(target)
        elif choice == "2":
            domain = input("Enter domain name: ")
            run_whois_lookup(domain)
        elif choice == "3":
            target = input("Enter target IP or subnet (e.g., 192.168.1.0/24): ")
            run_masscan(target)
        elif choice == "4":
            interface = input("Enter network interface (e.g., eth0, wlan0): ")
            duration = int(input("Enter capture duration (seconds): "))
            capture_packets(interface, duration)
        elif choice == "5":
            target_url = input("Enter target URL for SQL Injection: ")
            run_sqlmap(target_url)
        elif choice == "6":
            target = input("Enter target IP or domain: ")
            perform_metasploit_scan(target)
        elif choice == "7":
            interface = input("Enter network interface (e.g., eth0, wlan0): ")
            duration = int(input("Enter capture duration (seconds): "))
            run_wireshark(interface, duration)
        elif choice == "8":
            target_ip = input("Enter target IP for DDoS simulation: ")
            duration = int(input("Enter duration (seconds): "))
            run_ddos_attack(target_ip, duration)
        elif choice == "9":
            print("Exiting...")
            break
        else:
            print("Invalid option, try again.")

if __name__ == "__main__":
    main()
