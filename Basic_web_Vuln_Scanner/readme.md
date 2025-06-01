# Basic Web Vulnerability Scanner

This project is a basic web vulnerability scanner built using Python and PyQt5. It scans a target website for common vulnerabilities such as SQL Injection, Cross-Site Scripting (XSS), and exposure of sensitive information.

## Features

- **Crawling**: Recursively crawls the target website up to a specified depth.
- **SQL Injection Detection**: Tests for SQL injection vulnerabilities.
- **XSS Detection**: Tests for Cross-Site Scripting (XSS) vulnerabilities.
- **Sensitive Information Detection**: Searches for exposed sensitive information like emails, phone numbers, SSNs, and API keys.
- **GUI**: Provides a graphical user interface for easy interaction.

## Installation

1. Clone the repository:
    ```bash
    git clone "https://github.com/TimsTittus/H-C_Projects/tree/main/Basic_Web_Vuln_Scanner"
    cd Basic_Web_Vuln_Scanner
    ```

2. Install the required dependencies:
    ```bash
    pip install -r requirements.txt
    ```

## Usage

1. Run the application:
    ```bash
    python readme.md
    ```

2. Enter the target URL in the provided input field.
3. Configure the scan options and maximum crawl depth.
4. Click the "Start Scan" button to begin the scan.
5. View the scan log and results in the respective tabs.
6. Export the results to a text file if needed.

## Dependencies

- Python 3.x
- PyQt5
- requests
- BeautifulSoup4
- colorama

## Contributing

Contributions are welcome! Please open an issue or submit a pull request for any improvements or bug fixes.