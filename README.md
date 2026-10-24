# KaraQargha (Qara Qarğa) 🦅

[![Python Version](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-brightgreen.svg)](#)
[![OSINT Framework](https://img.shields.io/badge/tool-OSINT%20CLI-red.svg)](#)
[![Tests](https://img.shields.io/badge/tests-pytest%20passing-success.svg)](#)

```text
  _  __                    ___                       _       
 | |/ /__ _  __ _ _ __    / _ \ _ __ __ _ _ __   __| | __ _ 
 | ' // _` |/ _` | '_ \  | | | | '__/ _` | '_ \ / _` |/ _` |
 | . \ (_| | (_| | | | | | |_| | | | (_| | | | | (_| | (_| |
 |_|\_\__,_|\__,_|_| |_|  \___/|_|  \__,_|_| |_|\__,_|\__,_|
          Mini OSINT Framework v1.0 — by YOU
```

> **KaraQargha** (Black Crow) is a fast, modular, and terminal-first Open Source Intelligence (OSINT) investigation framework written in Python. It aggregates data breach records, email registrations across 120+ platforms, social username reconnaissance, phone carrier/region telemetry, IP geolocation with proxy/cloud detection, and public Gravatar/paste leaks into a single unified CLI tool.

---

## 📸 Banner & Terminal Preview

```
+-------------------------------------------------------------------------------+
|  _  __                    ___                       _                         |
| | |/ /__ _  __ _ _ __    / _ \ _ __ __ _ _ __   __| | __ _                    |
| | ' // _` |/ _` | '_ \  | | | | '__/ _` | '_ \ / _` |/ _` |                   |
| | . \ (_| | (_| | | | | | |_| | | | (_| | | | | (_| | (_| |                   |
| |_|\_\__,_|\__,_|_| |_|  \___/|_|  \__,_|_| |_|\__,_|\__,_|                   |
|          Mini OSINT Framework v1.0 — by YOU                                   |
|                                                                               |
| [~] Scanning breaches for target@example.com ...                              |
| [+] Found in 2 breach(es): Adobe, Canva                                       |
| [+] Account exists on: GitHub, Twitter, Spotify                               |
| [+] Phone Lookup: Valid (Mobile, San Francisco, CA)                           |
+-------------------------------------------------------------------------------+
```
*(Screenshot placeholder: `assets/karaqargha-demo.png`)*

---

## ⚡ Features & Modules

| Module | Source / Engine | Auth Required | Description |
|:---|:---|:---|:---|
| **`breach.py`** | [HaveIBeenPwned](https://haveibeenpwned.com) API v3 | `HIBP_API_KEY` (Free/Paid) | Checks known compromised credential databases, dates, and leaked data classes. |
| **`email.py`** | [Holehe](https://github.com/megadose/holehe) Engine | None | Async verification across 120+ online platforms (GitHub, Twitter, Spotify, etc.). |
| **`username.py`** | [Sherlock](https://github.com/sherlock-project/sherlock) Engine | None | Scans 400+ social networks for username existence with 10s request timeout. |
| **`phone.py`** | Google [libphonenumber](https://github.com/daviddrysdale/python-phonenumbers) | None (Offline) | E.164 normalization, carrier resolution, geographic region, and timezones. |
| **`ip.py`** | [ip-api.com](http://ip-api.com) JSON API | None | Geolocation (country, city, coordinates, ISP, ASN) + Proxy, VPN, and Cloud flags. |
| **`social.py`** | Gravatar MD5 & HIBP Pastes | Optional `HIBP_API_KEY` | Direct Gravatar avatar/profile resolution and pastebin breach searches. |

---

## 🚀 Installation

### Prerequisites
- Python **3.9+**
- Git

### 1. Clone the Repository
```bash
git clone https://github.com/Murad9100/KaraQargha.git
cd KaraQargha
```

### 2. Set Up a Virtual Environment (Optional)
```bash
# Windows (CMD / PowerShell):
py -m venv venv
venv\Scripts\activate

# Linux / macOS:
python3 -m venv venv
source venv/bin/activate
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

### 4. Install KaraQargha CLI
```bash
pip install -e .
```
Now you can invoke `karagargha` from any terminal session!

---

## 🔑 API Keys Configuration (Optional)

`KaraQargha` works right out of the box for IP geolocation, phone inspection, username lookups, Gravatar footprinting, and email service checks without any API keys.

To enable HaveIBeenPwned data breach and pastebin searches, set the `HIBP_API_KEY` environment variable:

- **Windows CMD**:
  ```cmd
  set HIBP_API_KEY=your_hibp_api_key_here
  ```
- **PowerShell**:
  ```powershell
  $env:HIBP_API_KEY="your_hibp_api_key_here"
  ```
- **Linux / macOS**:
  ```bash
  export HIBP_API_KEY="your_hibp_api_key_here"
  ```

---

## 💻 Usage & Examples

### 1. Email Breach & Registration Scan (`-e`, `--email`)
Scans HaveIBeenPwned breaches, holehe registrations, and Gravatar profiles:
```bash
karagargha -e user@example.com
```

### 2. Username Reconnaissance (`-u`, `--username`)
Scans hundreds of social networks for existing accounts with a 10-second timeout:
```bash
karagargha -u torvalds
```

### 3. Phone Number Geolocation & Carrier (`-p`, `--phone`)
Parses and auto-detects international and national formats:
```bash
karagargha -p +14155552671
```

**Sample Output:**
```text
======================
  Phone Intelligence
======================
[+] Phone Lookup Results for +14155552671:
  • Status:         Valid
  • E.164 Format:   +14155552671
  • International:  +1 415-555-2671
  • National:       (415) 555-2671
  • Region/City:    San Francisco, CA
  • Carrier:        Unknown
  • Timezone(s):    America/Los_Angeles
  • Line Type:      FIXED_LINE_OR_MOBILE
```

### 4. IP Threat & Geolocation Lookup (`-i`, `--ip`)
Geolocates IPv4/IPv6 addresses and inspects Proxy, VPN, and Datacenter flags:
```bash
karagargha -i 8.8.8.8
```

**Sample Output:**
```text
==================
  IP Geolocation
==================
[+] IP Geolocation Report for 8.8.8.8:
  • Country:        United States (US)
  • Region / State: Virginia
  • City / Zip:     Ashburn / 20149
  • Coordinates:    39.03, -77.5
  • Timezone:       America/New_York
  • ISP:            Google LLC
  • Organization:   Google Public DNS
  • AS Number:      AS15169 Google LLC
  • Proxy / VPN:    YES (Proxy/VPN/Tor)
  • Hosting / Cloud: YES (Data Center/Cloud)
  • Mobile Network: No
```

### 5. Comprehensive All-In-One Scan (`-a`, `--all`)
Runs email, social, leaks, and username reconnaissance for a single target:
```bash
karagargha -a target@example.com
```

### 6. Exporting Results (`-o`, `--output`)
Auto-detects format by file extension:
```bash
# Export structured JSON report
karagargha -p +14155552671 -o report.json

# Export clean, ANSI-stripped plain text report
karagargha -u johndoe -o investigation.txt
```

### 7. Headless JSON Output (`--json`)
Suppresses banners and animations, emitting pure machine-readable JSON to `stdout` for pipelines and scripting:
```bash
karagargha -i 1.1.1.1 --json | jq .
```

---

## 🧪 Running Unit Tests

KaraQargha includes an offline test suite for phone parsing, IP geolocation, breach handling, social detection, and file exports:

```bash
pytest -v tests/
```

---

## 🗺️ Roadmap

- [ ] **Domain & DNS Intelligence**: WHOIS lookup, DNS records (MX, TXT, SPF, DMARC), and subdomain enumeration.
- [ ] **Dark Web & Onion Search**: Integration with public Tor and breach search engines.
- [ ] **Shodan / Censys API**: Port scanning and service banner analysis for IP targets.
- [ ] **Interactive Relationship Graph**: HTML/Vis.js graph visualization exporting target linkages.
- [ ] **Multi-Target Batch Mode**: CSV/list input for high-volume automated investigative scanning.

---

## 🧩 New Modules (v2.0)

- Domain: `karagargha -d example.com`
- Email headers: `karagargha --headers raw_headers.txt`
- Crypto (BTC): `karagargha -c 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa`
- Image EXIF: `karagargha --image photo.jpg`
- Sanctions: `karagargha -s "Some Name"`

Reports are written under `reports/` when using `--html`; use `-o` for custom paths.

## 🧱 Adding a New Module

1. Create `karagargha/modules/mymodule.py`.
2. Subclass `BaseModule` from `karagargha.modules.base`.
3. Set `name`, `input_types`, `requires_key`.
4. Implement async `_run(self, target)` returning `(data, text)`.
5. Implement a sync `scan_*` wrapper if needed for the CLI.
6. The CLI auto-discovers `BaseModule` subclasses.

## ⚖️ LEGAL DISCLAIMER

> [!WARNING]
> **Use only on your own data or with explicit written permission.**
>
> This tool is developed strictly for educational purposes, authorized security auditing, threat intelligence research, and defensive OSINT analysis. The authors and contributors assume no liability and are not responsible for any misuse, damage, or legal infractions caused by this program. Always adhere to applicable local, national, and international cybersecurity laws.

---

## 📄 License

This project is licensed under the terms of the [MIT License](LICENSE).
