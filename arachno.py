#!/usr/bin/env python3
import requests
import argparse
import re
import difflib
import concurrent.futures
import time
import random
import logging
from urllib.parse import urlparse

# ANSI color codes for terminal output
RESET  = "\033[0m"
RED    = "\033[31m"
GREEN  = "\033[32m"
YELLOW = "\033[33m"
CYAN   = "\033[36m"

# Predefined User-Agents for random rotation
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 12_0) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.1 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; WOW64; rv:112.0) Gecko/20100101 Firefox/112.0"
]

def extract_title(html):
    """Extracts the <title> content from HTML."""
    match = re.search(r'<title>(.*?)</title>', html, re.IGNORECASE | re.DOTALL)
    return match.group(1).strip() if match else "No Title"

def compute_diff(baseline_text, test_text):
    """Computes a percentage difference between baseline and test responses."""
    sm = difflib.SequenceMatcher(None, baseline_text, test_text)
    return round((1 - sm.ratio()) * 100, 2)

def detect_vulnerabilities(resp, payload):
    """Detects potential vulnerabilities based on response content and payload."""
    vulns = []
    if resp:
        # Open Redirect: HTTP 301/302 with external Location header.
        if resp.status_code in [301, 302]:
            location = resp.headers.get("Location", "")
            if location:
                parsed = urlparse(location)
                if parsed.netloc and parsed.netloc != urlparse(resp.url).netloc:
                    vulns.append("Open Redirect")
        # LFI Check: directory traversal combined with system file markers.
        if "../" in payload and "root:" in resp.text:
            vulns.append("LFI")
        # Reflected Input: payload echoed back in response.
        if payload in resp.text:
            vulns.append("Reflected Input")
        # Simple XSS Check: presence of <script> tags.
        if "<script>" in resp.text.lower():
            vulns.append("Possible XSS")
        # SQL Injection indicator: common error messages.
        sql_errors = ["sql syntax", "mysql_fetch", "ORA-01756", "SQLSTATE"]
        for error in sql_errors:
            if error.lower() in resp.text.lower():
                vulns.append("SQL Injection")
                break
        # Command Injection indicator: shell error hints.
        cmd_errors = ["command not found", "sh:", "bash:"]
        for error in cmd_errors:
            if error.lower() in resp.text.lower():
                vulns.append("Command Injection")
                break
    return vulns

def log_result(method, payload, status, title, diff, vulns, log_file=None):
    """Logs the result of a fuzzing attempt to console and file if specified."""
    vuln_str = ", ".join(vulns) if vulns else "None"
    result_line = f"[{method}] Payload: {payload} | Status: {status} | Title: {title} | Diff: {diff}% | Vulns: {vuln_str}"
    print(f"{YELLOW}{result_line}{RESET}")
    if log_file:
        logging.info(result_line)

def load_wordlist(path):
    """Loads payloads from the specified file."""
    try:
        with open(path, "r") as f:
            return [line.strip() for line in f if line.strip()]
    except Exception as e:
        print(f"{RED}[ERROR]{RESET} Failed to load wordlist: {e}")
        return []

def send_request(method, url, data=None, cookies=None, headers=None, proxy=None, timeout=10, session=None):
    """Sends an HTTP request with the given parameters."""
    try:
        s = session or requests.Session()
        proxies = {"http": proxy, "https": proxy} if proxy else None
        if method == "GET":
            return s.get(url, headers=headers, timeout=timeout, proxies=proxies)
        elif method == "POST":
            return s.post(url, data=data, headers=headers, timeout=timeout, proxies=proxies)
        elif method == "COOKIE":
            # Convert cookie string "key=value; key2=value2" to a dict.
            cookie_dict = {}
            for part in cookies.split(";"):
                if "=" in part:
                    key, value = part.strip().split("=", 1)
                    cookie_dict[key] = value
            return s.get(url, cookies=cookie_dict, headers=headers, timeout=timeout, proxies=proxies)
    except Exception as e:
        print(f"{RED}[ERROR]{RESET} {method} request to {url} failed: {e}")
        return None

def get_baseline(method, url, template, headers, proxy, timeout, session):
    """Obtains a baseline response with the 'FUZZ' placeholder replaced by an empty string."""
    baseline_val = template.replace("FUZZ", "")
    if method == "GET":
        return send_request("GET", url.replace("FUZZ", ""), headers=headers, proxy=proxy, timeout=timeout, session=session)
    elif method == "POST":
        return send_request("POST", url, data=baseline_val, headers=headers, proxy=proxy, timeout=timeout, session=session)
    elif method == "COOKIE":
        return send_request("COOKIE", url, cookies=baseline_val, headers=headers, proxy=proxy, timeout=timeout, session=session)

def fuzz_worker(method, url, template, payload, baseline_text, headers, proxy, timeout, delay, random_agent, session, log_file):
    """Processes a single payload fuzzing attempt."""
    if delay:
        time.sleep(delay)
    local_headers = headers.copy() if headers else {}
    if random_agent:
        local_headers["User-Agent"] = random.choice(USER_AGENTS)
    if method == "GET":
        target = url.replace("FUZZ", payload)
        resp = send_request("GET", target, headers=local_headers, proxy=proxy, timeout=timeout, session=session)
    elif method == "POST":
        fuzzed_data = template.replace("FUZZ", payload)
        resp = send_request("POST", url, data=fuzzed_data, headers=local_headers, proxy=proxy, timeout=timeout, session=session)
    elif method == "COOKIE":
        fuzzed_cookie = template.replace("FUZZ", payload)
        resp = send_request("COOKIE", url, cookies=fuzzed_cookie, headers=local_headers, proxy=proxy, timeout=timeout, session=session)
    else:
        return
    if resp:
        diff = compute_diff(baseline_text, resp.text)
        title = extract_title(resp.text)
        vulns = detect_vulnerabilities(resp, payload)
        log_result(method, payload, resp.status_code, title, diff, vulns, log_file)

def fuzz_runner(method, url, template, wordlist, threads, headers, proxy, timeout, delay, random_agent, log_file):
    """Runs the fuzzing tasks concurrently using multiple threads."""
    session = requests.Session()
    baseline_resp = get_baseline(method, url, template, headers, proxy, timeout, session)
    baseline_text = baseline_resp.text if baseline_resp else ""
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        futures = []
        for payload in wordlist:
            futures.append(executor.submit(
                fuzz_worker, method, url, template, payload, baseline_text,
                headers, proxy, timeout, delay, random_agent, session, log_file
            ))
        concurrent.futures.wait(futures)

def main():
    # Simple, plain text header similar to nmap's startup message.
    print("Arachno - Advanced Web Fuzzer")
    
    parser = argparse.ArgumentParser(description="Arachno - Advanced Web Fuzzer")
    parser.add_argument("--url", required=True, help="Target URL with 'FUZZ' placeholder")
    parser.add_argument("--data", help="POST data with 'FUZZ' placeholder (for POST)")
    parser.add_argument("--cookies", help="Cookie string with 'FUZZ' placeholder (for COOKIE)")
    parser.add_argument("--wordlist", required=True, help="File with payloads (one per line)")
    parser.add_argument("--method", choices=["GET", "POST", "COOKIE"], required=True, help="Fuzzing method")
    parser.add_argument("--threads", type=int, default=20, help="Number of concurrent threads (default: 20)")
    parser.add_argument("--proxy", help="Proxy URL (e.g., http://127.0.0.1:8080)")
    parser.add_argument("--headers", nargs='*', help="Custom headers in 'Key:Value' format")
    parser.add_argument("--timeout", type=int, default=10, help="Request timeout in seconds (default: 10)")
    parser.add_argument("--delay", type=float, default=0, help="Delay between requests in seconds (default: 0)")
    parser.add_argument("--random-agent", action="store_true", help="Enable random User-Agent for each request")
    parser.add_argument("--output", help="Output file to log results")
    args = parser.parse_args()

    # Set up logging if an output file is provided.
    log_file = None
    if args.output:
        logging.basicConfig(filename=args.output, level=logging.INFO, format='%(asctime)s %(message)s')
        log_file = args.output

    # Process custom headers if provided.
    headers = {}
    if args.headers:
        for header in args.headers:
            if ":" in header:
                key, value = header.split(":", 1)
                headers[key.strip()] = value.strip()

    wordlist = load_wordlist(args.wordlist)
    if not wordlist:
        print(f"{RED}[ERROR]{RESET} Wordlist is empty or cannot be loaded.")
        return

    # Validate that the 'FUZZ' placeholder exists in the appropriate fields.
    if args.method == "GET":
        if "FUZZ" not in args.url:
            print(f"{RED}[ERROR]{RESET} For GET fuzzing, URL must contain 'FUZZ'.")
            return
        template = args.url
    elif args.method == "POST":
        if not args.data or "FUZZ" not in args.data:
            print(f"{RED}[ERROR]{RESET} For POST fuzzing, data must contain 'FUZZ'.")
            return
        template = args.data
    elif args.method == "COOKIE":
        if not args.cookies or "FUZZ" not in args.cookies:
            print(f"{RED}[ERROR]{RESET} For COOKIE fuzzing, cookies must contain 'FUZZ'.")
            return
        template = args.cookies

    start_time = time.time()
    print(f"{CYAN}[+] Starting {args.method} fuzzing with {args.threads} threads...{RESET}")
    fuzz_runner(args.method, args.url, template, wordlist, args.threads, headers, args.proxy, args.timeout, args.delay, args.random_agent, log_file)
    end_time = time.time()
    print(f"{GREEN}[+] Fuzzing completed in {round(end_time - start_time, 2)} seconds.{RESET}")

if __name__ == "__main__":
    main()
