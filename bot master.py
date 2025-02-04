import os
import subprocess
import pyautogui
import time
import tkinter as tk
from tkinter import simpledialog, messagebox

def run_nmap_scan(target):
    result = subprocess.run(["nmap", "-A", target], capture_output=True, text=True)
    messagebox.showinfo("Nmap Scan Result", result.stdout)

def run_whois_lookup(domain):
    result = subprocess.run(["whois", domain], capture_output=True, text=True)
    messagebox.showinfo("WHOIS Lookup Result", result.stdout)

def run_masscan(target):
    result = subprocess.run(["masscan", "-p1-65535", target], capture_output=True, text=True)
    messagebox.showinfo("Masscan Result", result.stdout)

def capture_packets(interface, duration):
    subprocess.run(["sudo", "tcpdump", "-i", interface, "-w", "capture.pcap", "-G", str(duration), "-W", "1"])
    messagebox.showinfo("Packet Capture", "Packet capture completed. Saved as capture.pcap")

def run_sqlmap(target_url):
    result = subprocess.run(["sqlmap", "-u", target_url, "--batch"], capture_output=True, text=True)
    messagebox.showinfo("SQL Injection Test", result.stdout)

def perform_metasploit_scan(target):
    subprocess.run(["msfconsole", "-q", "-x", f"use auxiliary/scanner/portscan/tcp; set RHOSTS {target}; run; exit"], capture_output=True, text=True)
    messagebox.showinfo("Metasploit Scan", "Metasploit scan completed.")

def open_wireshark_gui():
    subprocess.Popen(["wireshark"])
    time.sleep(5)
    pyautogui.hotkey('ctrl', 'i')
    time.sleep(2)
    pyautogui.press('enter')
    time.sleep(10)
    pyautogui.hotkey('ctrl', 'e')
    messagebox.showinfo("Wireshark Capture", "Wireshark capture completed.")

def open_burp_suite():
    subprocess.Popen(["burpsuite"])
    time.sleep(10)
    messagebox.showinfo("Burp Suite", "Burp Suite launched. Manually configure the proxy settings.")

def open_zap():
    subprocess.Popen(["zap"])
    time.sleep(10)
    messagebox.showinfo("OWASP ZAP", "OWASP ZAP launched. Perform web scanning manually.")

def open_firewall_settings():
    subprocess.Popen(["firewall-cmd", "--state"])
    messagebox.showinfo("Firewall Settings", "Firewall settings opened.")

def perform_ddos_attack(target_ip):
    subprocess.Popen(["hping3", "--flood", "--rand-source", "-p", "80", target_ip])
    messagebox.showinfo("DDoS Simulation", "DDoS simulation started.")

def main():
    root = tk.Tk()
    root.withdraw()

    options = {
        "Run Nmap Scan": lambda: run_nmap_scan(simpledialog.askstring("Nmap Scan", "Enter target IP or domain:")),
        "Perform WHOIS Lookup": lambda: run_whois_lookup(simpledialog.askstring("WHOIS Lookup", "Enter domain name:")),
        "Run Masscan": lambda: run_masscan(simpledialog.askstring("Masscan", "Enter target IP or subnet:")),
        "Capture Network Packets": lambda: capture_packets(simpledialog.askstring("Packet Capture", "Enter network interface:"), simpledialog.askinteger("Duration", "Enter duration (seconds):")),
        "Perform SQL Injection Test": lambda: run_sqlmap(simpledialog.askstring("SQL Injection", "Enter target URL:")),
        "Perform Metasploit Scan": lambda: perform_metasploit_scan(simpledialog.askstring("Metasploit Scan", "Enter target IP or domain:")),
        "Run Wireshark GUI": open_wireshark_gui,
        "Open Burp Suite": open_burp_suite,
        "Open OWASP ZAP": open_zap,
        "Open Firewall Settings": open_firewall_settings,
        "Simulate DDoS Attack": lambda: perform_ddos_attack(simpledialog.askstring("DDoS Simulation", "Enter target IP:")),
    }

    while True:
        choice = simpledialog.askstring("Security Practical Bot", "Select an option:\n" + "\n".join(options.keys()) + "\nExit")
        if choice == "Exit" or choice is None:
            break
        elif choice in options:
            options[choice]()
        else:
            messagebox.showerror("Error", "Invalid option, try again.")

if __name__ == "__main__":
    main()
