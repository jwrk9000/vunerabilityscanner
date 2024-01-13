# theHarvester scan + log to database
# bug_bounty_theHarvester.py


import subprocess
# sudo apt-get install theHarvester

def run_theHarvester_scan(target, output_file):
    theHarvester_command = f"theHarvester -d {target} -l 500 -b all -f {output_file}"
    subprocess.run(theHarvester_command, shell=True)

def open_new_tab():
    subprocess.run(["xdotool", "key", "ctrl+shift+t"])

if __name__ == "__main__":
    target_domain = input("Enter the target domain: ")

    # Define the common output file for Nmap, Nikto, and TheHarvester scans
    common_output_file = "bugbountydatabase_TheHarvester.txt"

    # Run TheHarvester scan and append results to bugbountydatabase_TheHarvester.txt
    run_theHarvester_scan(target_domain, common_output_file)

    # Open a new tab
    open_new_tab()

    print(f"TheHarvester scan results appended to {common_output_file}")