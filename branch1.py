#working crawler, sub domain enumerator 

import subprocess
import re
import time

def run_command(command):
    process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output, _ = process.communicate()
    return output.decode()

def scan_command_with_delay(command):
    run_command(f'gnome-terminal -- bash -c "{command}; echo scan completed; sleep 5"')

def scan_subdomains(subdomains):
    for subdomain in subdomains:
        print(f"Scanning subdomain: {subdomain}")
        commands = [
            f"nmap {subdomain} | grep 'open' | tee -a scan_results2.txt",
            f"nmap -sn {subdomain} | tee -a scan_results2.txt",
            f"dig +short {subdomain} | tee -a scan_results2.txt",
            f"amass enum -d {subdomain} -o | tee -a scan_results2.txt",
            f"subfinder -d {subdomain} | tee -a scan_results2.txt",
            f"assetfinder --subs-only {subdomain} | tee -a scan_results2.txt"
        ]
        for command in commands:
            scan_command_with_delay(command)
            # Wait for the command to complete before moving to the next one
            time.sleep(10)  # Adjust the delay as needed

def branch1(target):
    commands = [
        f"nmap {target} | grep 'open' | tee -a scan_results.txt",
        f"nmap -sn {target} | tee -a scan_results.txt",
        f"dig +short {target} | tee -a scan_results.txt",
        f"amass enum -d {target} -o | tee -a scan_results.txt",
        f"subfinder -d {target} | tee -a scan_results.txt",
        f"assetfinder --subs-only {target} | tee -a scan_results.txt"
    ]
    for command in commands:
        scan_command_with_delay(command)
        # Wait for the command to complete before moving to the next one
        time.sleep(10)  # Adjust the delay as needed

def scan_com_domains(com_domains, filename="scan_results.txt"):
    for domain in com_domains:
        print(f"Scanning domain: {domain}")
        commands = [
            f"nmap {domain} | grep 'open' | tee -a scan_results2.txt",
            f"nmap -sn {domain} | tee -a scan_results2.txt",
            f"dig +short {domain} | tee -a scan_results2.txt",
            f"amass enum -d {domain} -o | tee -a scan_results2.txt",
            f"subfinder -d {domain} | tee -a scan_results2.txt",
            f"assetfinder --subs-only {domain} | tee -a scan_results2.txt"
        ]
        for command in commands:
            scan_command_with_delay(command)
            # Wait for the command to complete before moving to the next one
            time.sleep(10)  # Adjust the delay as needed

# Original target host
target_host = "starbucks.com"
branch1(target_host)

# Wait for the initial scan to complete
time.sleep(10)  # Adjust the delay as needed

# Get .com domains from scan_results.txt
com_domains = []
with open("scan_results.txt", "r") as file:
    for line in file:
        if line.strip().endswith(".com"):
            com_domains.append(line.strip())

# Run scans on .com subdomains found in scan_results.txt
scan_com_domains(com_domains)

# Wait for all scans to complete
time.sleep(10 * len(com_domains))  # Adjust the delay as needed

# Close the terminal tabs
subprocess.run(['xdotool', 'key', 'ctrl+shift+w'])