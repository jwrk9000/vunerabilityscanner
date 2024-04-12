







import subprocess
import time
import re
import nmap

scanned_subdomains = set()

def run_command(command):
    process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output, _ = process.communicate()
    return output.decode()

def scan_command_with_delay(command):
    run_command(f'gnome-terminal -- bash -c "{command}; echo scan completed; sleep 5"')

def is_domain_or_ip(subdomain):
    if subdomain.endswith('.com') or re.match(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', subdomain):
        return True
    return False

def scan_subdomains(subdomains):
    for subdomain in subdomains:
        if subdomain not in scanned_subdomains and is_domain_or_ip(subdomain):
            print(f"Scanning subdomain: {subdomain}")
            commands = [
                f"amass enum -d {subdomain} | tee -a scan_results2.txt",
                f"subfinder -d {subdomain} | tee -a scan_results2.txt",
                f"assetfinder --subs-only {subdomain} | tee -a scan_results2.txt"
            ]
            for command in commands:
                scan_command_with_delay(command)
                time.sleep(20)
            scanned_subdomains.add(subdomain)

def branch1(target):
    commands = [
        f"amass enum -d {target} | tee -a scan_results.txt",
        f"subfinder -d {target} | tee -a scan_results.txt",
        f"assetfinder --subs-only {target} | tee -a scan_results.txt"
    ]
    for command in commands:
        scan_command_with_delay(command)
        time.sleep(20)

def scan_com_domains(com_domains, filename="scan_results.txt"):
    for domain in com_domains:
        print(f"Scanning domain: {domain}")
        commands = [
            f"amass enum -d {domain} -o | tee -a scan_results2.txt",
            f"subfinder -d {domain} | tee -a scan_results2.txt",
            f"assetfinder --subs-only {domain} | tee -a scan_results2.txt"
        ]
        for command in commands:
            scan_command_with_delay(command)
            time.sleep(10)

def nmap_scan(domain):
    try:
        nm = nmap.PortScanner()
        nm.scan(domain, arguments='-p 1-1000')
        with open('ports.txt', 'a') as file:
            for host in nm.all_hosts():
                for proto in nm[host].all_protocols():
                    lport = nm[host][proto].keys()
                    for port in lport:
                        file.write(f"{host};{domain};{proto};{port};{nm[host][proto][port]['name']};{nm[host][proto][port]['state']}\n")
    except Exception as e:
        print(f"An error occurred while scanning domain {domain}: {e}")

def mainloopportrecon(filename, filename2):
    try:
        with open(filename, 'r') as file:
            domains = file.readlines()
            for domain in domains:
                domain = domain.strip()
                print(f"Scanning domain: {domain}")
                nmap_scan(domain)
    except Exception as e:
        print(f"An error occurred while reading the file: {e}")

def run_nikto_on_domains(file1, file2, output_file):
    with open(file1, 'r') as f1, open(file2, 'r') as f2, open(output_file, 'w') as out:
        for file in [f1, f2]:
            for line in file:
                domain = line.strip()
                if domain:  
                    print(f"Scanning domain: {domain}")
                    command = f"nikto -h {domain} -C all -Plugins 'test, outdated, ods, nikto'"
                    try:
                        result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=30)
                        print(f"Results for domain: {domain}")
                        print(result.stdout)
                        print(result.stderr)
                        out.write(f"Results for domain: {domain}\n")
                        out.write(result.stdout)
                        out.write(result.stderr)
                        out.write('\n\n')
                    except subprocess.TimeoutExpired:
                        print(f"Scan for {domain} timed out. Moving to the next domain.")
                    except Exception as e:
                        print(f"Error occurred while scanning {domain}: {e}")

if __name__ == "__main__":
    target_host = ""
    branch1(target_host)
    time.sleep(20)
    com_domains = []
    with open("scan_results.txt", "r") as file:
        for line in file:
            if line.strip().endswith(".com"):
                com_domains.append(line.strip())
    scan_com_domains(com_domains)
    time.sleep(20 * len(com_domains))
    mainloopportrecon('scan_results.txt', 'scan_results2.txt')
    run_nikto_on_domains('scan_results.txt', 'scan_results2.txt', 'scan_results5.txt')
