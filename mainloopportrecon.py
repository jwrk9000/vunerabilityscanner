import nmap

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
    mainloopportrecon('scan_results.txt', 'scan_results2.txt')
