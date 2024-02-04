
logging

import logging

def setup_logging():
    # Create a custom formatter for log messages
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')

    # Create a root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG)

    # Create a file handler for detailed logs
    file_handler = logging.FileHandler('bug_bounty_automation.log')
    file_handler.setFormatter(formatter)
    file_handler.setLevel(logging.DEBUG)  # Adjust the level as needed
    root_logger.addHandler(file_handler)

    # Create a console handler for INFO and above messages
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    console_handler.setLevel(logging.INFO)
    root_logger.addHandler(console_handler)

    # Create custom loggers for different components
    web_crawler_logger = logging.getLogger('web_crawler')
    web_crawler_logger.setLevel(logging.DEBUG)  # Adjust the level as needed

    vulnerability_scanner_logger = logging.getLogger('vulnerability_scanner')
    vulnerability_scanner_logger.setLevel(logging.DEBUG)  # Adjust the level as needed

    return root_logger, web_crawler_logger, vulnerability_scanner_logger

# Usage example
if __name__ == "__main__":
    root_logger, web_crawler_logger, vulnerability_scanner_logger = setup_logging()

    try:
        # Simulate an error in web crawler
        1 / 0
    except Exception as e:
        web_crawler_logger.error(f"An error occurred in the web crawler: {e}")

    try:
        # Simulate an error in vulnerability scanner
        raise ValueError("Simulated vulnerability found")
    except ValueError as ve:
        vulnerability_scanner_logger.error(f"Vulnerability scanner error: {ve}")
