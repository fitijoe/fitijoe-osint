# 🕵️ fitijoe OSINT Intelligence Gatherer v1.0

Advanced OSINT & Target Intelligence tool for Bug Bounty Hunters.
Built by fitijoe (MohamedSuleiman)

## Features
- DNS & WHOIS intelligence
- Subdomain enumeration (907+ found on large targets)
- Email & employee harvesting
- Technology fingerprinting
- GitHub secret hunting
- Google dorks generator
- Breach & reputation check
- Exploitation guidance

## Installation
```bash
git clone https://github.com/fitijoe/fitijoe-osint.git
cd fitijoe-osint
sudo apt install curl dig whois -y
```

## Usage
```bash
# Full scan
python3 fitijoe-osint.py -d target.com

# Single module
python3 fitijoe-osint.py -d target.com --module subdomains
python3 fitijoe-osint.py -d target.com --module emails
python3 fitijoe-osint.py -d target.com --module dorks
```

## Author
fitijoe (MohamedSuleiman)
- GitHub: https://github.com/fitijoe
- HackerOne: https://hackerone.com/fitijoe
- Bugcrowd: https://bugcrowd.com/fitijoe

## Legal & Ethical Use
- Only use on domains you own or have written permission to research
- Always join the official bug bounty program before testing
- This tool only collects publicly available information
- The author is not responsible for misuse
