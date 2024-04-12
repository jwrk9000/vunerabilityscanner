import mainloopsubrecon
import mainloopportrecon
import nikto
#import dirbrute

def mainloop():
    try:
        mainloopsubrecon.mainloopsubrecon()
    except Exception as e:
        print(f"An error occurred in mainloopsubrecon: {e}")
    
    try:
        mainloopportrecon.mainloopportrecon('scan_results.txt', 'scan_results2.txt')
    except Exception as e:
        print(f"An error occurred in mainloopportrecon: {e}")

    try:
        nikto.run_nikto_on_domains('scan_results.txt', 'scan_results2.txt', 'scan_results5.txt')
    except Exception as e:
        print(f"An error occurred in nikto: {e}")

    # Add dirbrute function call here if needed

if __name__ == "__main__":
    mainloop()
