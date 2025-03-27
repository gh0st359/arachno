# arachno
Arachno is an advanced, high-performance web fuzzer designed for security researchers, penetration testers, and anyone looking to uncover hidden vulnerabilities in web applications. Built with a focus on efficiency and precision, Arachno leverages multi-threading, customizable configurations, and advanced detection techniques to provide deep insight into potential security flaws.

Key Features:
	•	Multi-Threaded Fuzzing:
Harness the power of concurrent scanning using Python’s ThreadPoolExecutor to rapidly test large payload lists.
	•	Advanced Vulnerability Detection:
Automatically identify common web vulnerabilities such as open redirects, Local File Inclusion (LFI), reflected input, potential XSS, SQL injection, and command injection clues.
	•	Random User-Agent Rotation:
Dynamically rotate User-Agent headers to better mimic real-world traffic and bypass simple security filters.
	•	Customizable Configuration:
Easily set custom headers, proxies, request delays, and timeouts to fine-tune your testing environment and evade detection.
	•	Flexible Input Modes:
Supports GET, POST, and COOKIE fuzzing by using a placeholder (FUZZ) in your target URL, data, or cookie strings, seamlessly integrating with your custom wordlists.
	•	Logging & Reporting:
Optionally log detailed results to a file for in-depth analysis and reporting.

Usage Example:

python arachno.py --url "http://example.com/page?param=FUZZ" --wordlist payloads.txt --method GET --threads 20 --random-agent --output results.log

Requirements:
	•	Python 3.x
	•	requests library

Disclaimer: Don't break the law pls. 

