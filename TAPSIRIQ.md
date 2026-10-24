You are upgrading my existing project KaraQargha (a Python OSINT command-line framework, GitHub: Murad9100/KaraQargha). First read the whole codebase and README, then show me a short plan, then implement step by step with a git commit after each step.



GOALS

1\. New identity. The current ASCII banner looks like the word "Kaan", not "KaraQargha". Replace it with a proper banner that clearly spells KARAQARGHA (use the pure-Python pyfiglet library, plus a small crow ASCII art), colored with colorama, with the subtitle "OSINT Framework v2.0 - by Murad". Add a clean colored output style: section headers, \[+]/\[-]/\[!] status icons, a progress indicator, and a summary at the end.

2\. Architecture. Every data source is one module in karagargha/modules/ with a common base class (name, input types, requires\_key flag, async run()). The CLI auto-discovers modules. Modules that need an API key are optional and are skipped with a clear message when the key is missing in .env. Add rate limiting, timeouts and retries; one failing module must never stop the others.

3\. Output. Terminal report plus --json and --html report files saved under a reports/ folder.

4\. Modules to add (free sources, no key needed by default). Before using any endpoint, check its official documentation; if an endpoint no longer exists or needs payment, disable that module and tell me instead of guessing:

&#x20;  - email: syntax + MX validation, disposable-domain check, Gravatar, breach check via the free XposedOrNot API (breach names, dates, data classes only), infostealer exposure check via Hudson Rock's free public OSINT API (status only), keep the existing holehe check, HIBP as an optional module only if HIBP\_API\_KEY is set; plus an email header analyzer (user gives a file with raw headers: parse the Received chain, originating IP, SPF/DKIM/DMARC results)

&#x20;  - domain: RDAP/WHOIS, DNS records (dnspython), subdomains via crt.sh certificate transparency, SSL certificate details, Wayback Machine snapshots

&#x20;  - ip: geolocation and ASN, reverse DNS, open ports and known vulnerabilities from Shodan InternetDB (free, no key), optional AbuseIPDB if a key is set

&#x20;  - username: check 300+ sites using the public WhatsMyName dataset (wmn-data.json), concurrent with trio/httpx, with a false-positive warning

&#x20;  - phone: keep the offline phonenumbers lookup (country, carrier, line type, timezone); no account discovery

&#x20;  - image: EXIF metadata including GPS coordinates (Pillow) and links to reverse-image-search services (do not automate them)

&#x20;  - crypto: Bitcoin address and transaction summary via a free public explorer API

&#x20;  - sanctions: check a name or entity against the public OFAC SDN list (downloaded and cached locally)

5\. Safety rules (keep them in code and README):

&#x20;  - Never display, store or download plaintext passwords, password hashes or full leaked records. Breach modules return only breach name, date and the types of data exposed.

&#x20;  - On first run and in the README show a notice: use the tool only on your own data, your own assets, or with the owner's permission.

&#x20;  - No scraping of logged-in social networks, no discovery of a person's WhatsApp/Telegram accounts, no people-search by name.

6\. Compatibility. Must run on Windows with Python 3.12+ using only pure-Python or prebuilt-wheel dependencies (nothing that needs a C++ compiler). Remove or replace anything that pulls in pandas. Update requirements.txt, setup.py and the README (English, with usage examples for every command and an "adding a new module" section). Add basic pytest tests with mocked network calls.

7\. Never hardcode API keys. Keep .env in .gitignore and update .env.example.



When finished, run the tests and tell me, in Azerbaijani, what works, what was disabled and why.

