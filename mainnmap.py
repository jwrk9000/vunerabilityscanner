import subprocess

import time

import re

import nmap

#           ;               ,          

#         ,;                 '.        

#        ;:                   :;        

#       ::                     ::      

#       ::                     ::      

#       ':                     :        

#        :.                    :        

#     ;' ::                   ::  '    

#    .'  ';                   ;'  '.    

#   ::    :;                 ;:    ::  

#   ;      :;.             ,;:     ::  

#   :;      :;:           ,;"      ::  

#   ::.      ':;  ..,.;  ;:'     ,.;:  

#    "'"...   '::,::::: ;:   .;.;""'    

#        '"""....;:::::;,;.;"""        

#    .:::.....'"':::::::'",...;::::;.  

#   ;:' '""'"";.,;:::::;.'""""""  ':;  

#  ::'         ;::;:::;::..         :;  

# ::         ,;:::::::::::;:..       ::

# ;'     ,;;:;::::::::::::::;";..    ':.

#::     ;:"  ::::::"""'::::::  ":     ::

# :.    ::   ::::::;  :::::::   :     ;

#  ;    ::   :::::::  :::::::   :    ;  

#   '   ::   ::::::....:::::'  ,:   '  

#    '  ::    :::::::::::::"   ::      

#       ::     ':::::::::"'    ::      

#       ':       """""""'      ::      

#        ::                   ;:        

#        ':;                 ;:"        

#          ';              ,;'          

#            "'           '"            

#              '

import subprocess

def run_subfinder(target):

    try:

        # Run Subfinder command and capture the output

        result = subprocess.run(['subfinder', '-d', target, '-o', 'scan_results.txt'], capture_output=True, text=True)

        # Check if the command was successful

        if result.returncode == 0:

            print(f"Subfinder completed successfully. Subdomains are saved in 'scan_results.txt'.")

            # Read the output file and display the subdomains

            with open('scan_results.txt', 'r') as file:

                subdomains = file.readlines()

                for subdomain in subdomains:

                    print(subdomain.strip())

        else:

            print(f"Subfinder encountered an error: {result.stderr}")

    except Exception as e:

        print(f"An error occurred: {e}")

if __name__ == "__main__":

    # Prompt user for target domain or IP address

    target = input("Enter the domain or IP address to scan: ")

    run_subfinder(target)

#/////////////////////////////

import nmap

def scan_vulnerabilities(subdomains):

    # Create an instance of the PortScanner class

    nm = nmap.PortScanner()

    # Loop through the list of subdomains and scan each one

    for subdomain in subdomains:

        subdomain = subdomain.strip()  # Remove any leading/trailing whitespace or newline characters

        print(f"Scanning {subdomain} for vulnerabilities...")

        try:

            # Run the Nmap scan with the --script vuln option

            nm.scan(subdomain, arguments='--script vuln')

            # Retrieve and print the scan results

            for host in nm.all_hosts():

                print(f"Host: {host} ({nm[host].hostname()})")

                print(f"State: {nm[host].state()}")

                for proto in nm[host].all_protocols():

                    print(f"Protocol: {proto}")

                    lport = nm[host][proto].keys()

                    for port in lport:

                        print(f"Port: {port}\tState: {nm[host][proto][port]['state']}")

                        if 'script' in nm[host][proto][port]:

                            for script in nm[host][proto][port]['script']:

                                print(f"Script: {script}\nOutput: {nm[host][proto][port]['script'][script]}")

        except Exception as e:

            print(f"Error scanning {subdomain}: {e}")

if __name__ == "__main__":

    # Initialize an empty list to store all subdomains

    subdomains = []

    # Read subdomains from scan_results.txt

    with open('scan_results.txt', 'r') as file:

        subdomains.extend(file.readlines())

    # Call the scan_vulnerabilities function with the list of subdomains

    scan_vulnerabilities(subdomains)
