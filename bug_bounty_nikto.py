# nikkto scan + log to database
# bug_bounty_nikto.py


import subprocess
#sudo apt-get install nikto
def run_nikto_scan(target, output_file):
    nikto_command = f"nikto -h {target} -o {output_file} -Format txt"
    subprocess.run(nikto_command, shell=True)

def open_new_tab():
    subprocess.run(["xdotool", "key", "ctrl+shift+t"])

if __name__ == "__main__":
    target_domain = input("Enter the target domain: ")

    # Define the common output file for both Nmap and Nikto scans
    common_output_file = "bugbountydatabase_nikto.txt"

    # Run Nikto scan and append results to bugbountydatabase_nikto.txt
    run_nikto_scan(target_domain, common_output_file)

    # Open a new tab
    open_new_tab()

    print(f"Nikto scan results appended to {common_output_file}")