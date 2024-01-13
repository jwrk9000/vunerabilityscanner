# bug_bounty_automation.py

import subprocess

def run_nmap_scan(target, output_file):
    nmap_command = f"nmap {target} -oN {output_file}"
    subprocess.run(nmap_command, shell=True)

def run_theharvester(target, output_file):
    theharvester_command = f"theharvester -d {target} -l 500 -b all -f {output_file}"
    subprocess.run(theharvester_command, shell=True)

def run_nikto_scan(target, output_file):
    nikto_command = f"nikto -h {target} -o {output_file} -Format txt"
    subprocess.run(nikto_command, shell=True)

def count_occurrences(file_path, keywords):
    try:
        with open(file_path, 'r') as file:
            content = file.read().lower()
            occurrences = {keyword: content.count(keyword) for keyword in keywords}
            return occurrences
    except FileNotFoundError:
        print(f"File not found: {file_path}")
        return {}

def save_occurrences_to_file(output_file_path, occurrences):
    with open(output_file_path, 'a') as output_file:
        for keyword, count in occurrences.items():
            output_file.write(f"The word '{keyword}' is mentioned {count} times.\n")

if __name__ == "__main__":
    target_domain = input("Enter the target domain: ")

    # Define output files for Nmap, TheHarvester, and Nikto scans
    nmap_output_file = "bugbountydatabase_nmap.txt"
    theharvester_output_file = "bugbountydatabase_theharvester.txt"
    nikto_output_file = "bugbountydatabase_nikto.txt"

    # Run Nmap scan
    run_nmap_scan(target_domain, nmap_output_file)

    # Run TheHarvester
    run_theharvester(target_domain, theharvester_output_file)

    # Run Nikto scan
    run_nikto_scan(target_domain, nikto_output_file)

    # Combine all results into a single file for further analysis
    combined_output_file = "bugbountydatabase_combined.txt"
    subprocess.run(["cat", nmap_output_file, theharvester_output_file, nikto_output_file, ">", combined_output_file], shell=True)

    # Specify the keywords to search for (case-insensitive)
    keywords_to_search = ["cookie", "admin", "login"]

    # Count occurrences of the keywords in the combined file
    occurrences = count_occurrences(combined_output_file, keywords_to_search)

    # Save occurrences to another file
    keywords_occurrences_file = "bugbountydatabase_keywords.txt"
    save_occurrences_to_file(keywords_occurrences_file, occurrences)

    print(f"Results saved to {combined_output_file} and {keywords_occurrences_file}")
