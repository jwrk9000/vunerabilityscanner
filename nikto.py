import subprocess

def run_nikto_on_domains(file1, file2, output_file):
    with open(file1, 'r') as f1, open(file2, 'r') as f2, open(output_file, 'w') as out:
        for file in [f1, f2]:
            for line in file:
                domain = line.strip()
                if domain:  # Ensure the line is not empty
                    print(f"Scanning domain: {domain}")
                    command = f"nikto -h {domain} -C all -Plugins 'test, outdated, ods, nikto'"
                    try:
                        result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=30)
                        # Print output to terminal
                        print(f"Results for domain: {domain}")
                        print(result.stdout)
                        print(result.stderr)
                        # Write output to file
                        out.write(f"Results for domain: {domain}\n")
                        out.write(result.stdout)
                        out.write(result.stderr)
                        out.write('\n\n')
                    except subprocess.TimeoutExpired:
                        print(f"Scan for {domain} timed out. Moving to the next domain.")
                    except Exception as e:
                        print(f"Error occurred while scanning {domain}: {e}")

# Example usage:
run_nikto_on_domains('scan_results.txt', 'scan_results2.txt', 'scan_results5.txt')
