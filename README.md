# KaraQargha (Qara Qarğa) 🦅

[![Python Version](https://img.shields.io/badge/python-3.12%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-brightgreen.svg)](#)
[![OSINT Framework](https://img.shields.io/badge/tool-OSINT%20CLI-red.svg)](#)
[![Tests](https://img.shields.io/badge/tests-pytest%20passing-success.svg)](#)

```text
  __ __ ___    ____  ___   ____    ___    ____  ________  _____
 / //_//   |  / __ \/   | / __ \  /   |  / __ \/ ____/ / / /   |
/ ,<  / /| | / /_/ / /| |/ / / / / /| | / /_/ / / __/ /_/ / /| |
/ /| |/ ___ |/ _, _/ ___ / /_/ / / ___ |/ _, _/ /_/ / __  / ___ |
/_/ |_/_/  |_/_/ |_/_/  |_\___\_\/_/  |_/_/ |_|\____/_/ /_/_/  |_|

       ___
      (   )
     (  v  )    . . .
      (   )   . . . .
       " "   . . . . .

OSINT Framework v2.0 - by Murad
```

> **KaraQargha** (Black Crow) is a fast, modular, and terminal-first Open Source Intelligence (OSINT) investigation framework written in Python. It aggregates data breach records, email registrations, username reconnaissance, phone validation, IP geolocation, domain intelligence, cryptocurrency summaries, image metadata, and sanctions screening into a single unified CLI tool.

---

## ⚠️ Notice

Use this tool **only on your own data, your own assets, or with the owner's explicit permission**. It is intended for authorized security research, threat intelligence, and defensive OSINT analysis. Unauthorized use against third parties may be illegal.

---

## ⚡ Features & Modules

| Module | Source / Engine | Auth Required | Description |
|:---|:---|:---|:---|
| `breach.py` | HaveIBeenPwned (optional), XposedOrNot (free) | Optional `HIBP_API_KEY` | Breach names, dates, and exposed data classes only. |
| `email.py` | Holehe (optional), XposedOrNot, Hudson Rock | None | Syntax + MX validation, disposable check, breach + infostealer status, account registration, email header analysis. |
| `domain.py` | RDAP, dnspython, crt.sh, SSL, Wayback | None | WHOIS/RDAP, DNS records, subdomains, certificate, snapshots. |
| `username.py` | WhatsMyName dataset | None | 300+ site checks via concurrent httpx (false positives possible). |
| `phone.py` | python-phonenumbers | None (offline) | E.164, carrier, region, timezone, line type. |
| `ip.py` | ip-api.com, Shodan InternetDB, AbuseIPDB | Optional `ABUSEIPDB_API_KEY` | Geolocation, reverse DNS, open ports, vulnerabilities. |
| `crypto.py` | mempool.space | None | Bitcoin address and transaction summary. |
| `image.py` | Pillow | None | EXIF metadata incl. GPS + reverse-image-search links. |
| `sanctions.py` | OFAC SDN list (cached) | None | Name/entity screening (local cached CSV). |
| `social.py` | Gravatar MD5, HIBP pastes | Optional `HIBP_API_KEY` | Public profile and paste leak metadata. |

Safety: no plaintext passwords/hashes/full leaked records are stored or displayed. Social registration checks may produce false positives.

---

## 🚀 Installation

### Prerequisites
- Python **3.12+**
- Git

### 1. Clone
```bash
git clone https://github.com/Murad9100/KaraQargha.git
cd KaraQargha
```

### 2. Virtual Environment
```bash
# Windows
py -m venv venv
venv\Scripts\activate

# Linux / macOS
python3 -m venv venv
source venv/bin/activate
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
pip install -e .
```

---

## 🔑 API Keys (optional)

```bash
cp .env.example .env
# edit .env and set keys
```

Supported:
- `HIBP_API_KEY` — enables HIBP breaches/pastes
- `ABUSEIPDB_API_KEY` — enables AbuseIPDB reputation

---

## 💻 Usage & Examples

Run without arguments to open the interactive menu:

```bash
karagargha
```


### Email
```bash
karagargha -e user@example.com
```

### Username
```bash
karagargha -u torvalds
```

### Phone
```bash
karagargha -p +14155552671
```

### IP
```bash
karagargha -i 8.8.8.8
```

### Domain
```bash
karagargha -d example.com
```

### Email header analysis
```bash
karagargha --headers raw_headers.txt
```

### Crypto
```bash
karagargha -c 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa
```

### Image EXIF
```bash
karagargha --image photo.jpg
```

### Sanctions
```bash
karagargha -s "Some Name"
```

### Comprehensive
```bash
karagargha -a target@example.com
```

### Export
```bash
karagargha -p +14155552671 -o report.json
karagargha -u johndoe -o investigation.txt
karagargha -i 1.1.1.1 --html
```

### Headless JSON
```bash
karagargha -i 1.1.1.1 --json | jq .
```

---

## 🧪 Tests

```bash
pytest -v tests/
```

Network calls are mocked; core modules work offline.

---

## 🧱 Adding a New Module

1. Create `karagargha/modules/mymodule.py`.
2. Subclass `BaseModule` from `karagargha.modules.base`.
3. Set `name`, `input_types`, `requires_key`.
4. Implement async `_run(self, target)` returning `(data, text)`.
5. Add a sync wrapper if used by the CLI.
6. Auto-discovery picks up `BaseModule` subclasses.

Example skeleton:
```python
from karagargha.modules.base import BaseModule

class MyModule(BaseModule):
    name = "mymodule"
    input_types = {"email"}
    requires_key = None

    async def _run(self, target, **kwargs):
        return ({"ok": True}, "done")
```

---

## ⚖️ Legal Disclaimer

Use only on your own data or with explicit written permission. The authors assume no liability for misuse.

---

## 📝 Notes & Limitations

- Domain/username/sanctions lookups use public services and may take longer depending on network conditions.
- Public registration checks can produce false positives.
- No passwords, hashes, or full leaked records are displayed.
- IP geolocation API (`ip-api.com`) has request limits for heavy usage.

## 📄 License

MIT License. See [LICENSE](LICENSE).