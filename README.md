# script framework that scans domains for vulnerabilities

#   this will be an attempt to create a full 0-100 series of
#   scripts,functions,etc that can be run to automate bug bounty
#   searches and scans and enumerations and logging of data etc.
#   initial domain will set off a chain of events.
#   nmap scan,nikto scan, theHarvester scan, maybe amass scan?
#   results are sent to text file,(database)
#
#


when in kali:
cd ~/Downloads
ls
python3 bug_bounty_automation.py
