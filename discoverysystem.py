
discovery

import requests
import logging
import concurrent.futures
import time
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry

def configure_session():
    session = requests.Session()
    retry_strategy = Retry(
        total=3,
        backoff_factor=1,
        status_forcelist=[429, 500, 502, 503, 504],
    )
    adapter = HTTPAdapter(max_retries=retry_strategy)
    session.mount('http://', adapter)
    session.mount('https://', adapter)
    return session

def discover_content(target_url, wordlist_path, output_file, extensions=None, status_codes=None):
    try:
        with open(wordlist_path, 'r') as wordlist_file:
            wordlist = [line.strip() for line in wordlist_file.readlines()]

        session = configure_session()

        start_time = time.time()
        discovered_urls = []

        with concurrent.futures.ThreadPoolExecutor() as executor:
            futures = [executor.submit(
                discover_url,
                session,
                target_url,
                entry,
                discovered_urls,
                extensions,
                status_codes
            ) for entry in wordlist]

            concurrent.futures.wait(futures)

        end_time = time.time()

        if output_file:
            with open(output_file, 'w') as out_file:
                out_file.write('\n'.join(discovered_urls))

        total_requests = len(wordlist)
        successful_discoveries = len(discovered_urls)
        elapsed_time = end_time - start_time

        print("\n===== Summary Statistics =====")
        print(f"Total Requests: {total_requests}")
        print(f"Successful Discoveries: {successful_discoveries}")
        print(f"Elapsed Time: {elapsed_time:.2f} seconds")

    except FileNotFoundError:
        logging.error(f"Wordlist file not found: {wordlist_path}")
    except Exception as e:
        logging.error(f"An error occurred: {e}")

def discover_url(session, target_url, entry, discovered_urls, extensions, status_codes):
    discovery_url = f"{target_url}/{entry}"

    try:
        response = session.get(discovery_url, headers={'User-Agent': 'Mozilla/5.0'}, timeout=10)

        if response.status_code in (status_codes or [200]):
            logging.info(f"Discovered: {discovery_url}")
            discovered_urls.append(discovery_url)
        elif response.status_code == 403:
            logging.warning(f"Forbidden: {discovery_url}")

        if extensions:
            for ext in extensions:
                ext_url = f"{discovery_url}.{ext}"
                ext_response = session.get(ext_url, headers={'User-Agent': 'Mozilla/5.0'}, timeout=10)
                if ext_response.status_code in (status_codes or [200]):
                    logging.info(f"Discovered (with extension): {ext_url}")
                    discovered_urls.append(ext_url)

    except requests.RequestException as req_ex:
        logging.error(f"Request failed for {discovery_url}: {req_ex}")

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description='Web Content Discovery Tool')
    parser.add_argument('target_url', help='Target URL to scan')
    parser.add_argument('wordlist_path', help='Path to wordlist file')
    parser.add_argument('--output-file', help='Path to output file for discovered URLs')
    parser.add_argument('--extensions', nargs='+', help='List of file extensions to brute-force')
    parser.add_argument('--status-codes', nargs='+', type=int, help='List of acceptable HTTP status codes')

    args = parser.parse_args()

    logging.basicConfig(filename='content_discovery.log', level=logging.INFO, format='%(asctime)s - %(levelname)s: %(message)s')

    print("\n===== Content Discovery Tool =====")
    print(f"Target URL: {args.target_url}")
    print(f"Wordlist: {args.wordlist_path}")
    print(f"Extensions: {args.extensions}")
    print(f"Status Codes: {args.status_codes}")

    discover_content(args.target_url, args.wordlist_path, args.output_file, args.extensions, args.status_codes)
