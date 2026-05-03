#!/usr/bin/env python3
"""
==============================================================================
  fitijoe OSINT INTELLIGENCE GATHERER v1.0
  Author : fitijoe (MohamedSuleiman)
  GitHub : https://github.com/fitijoe
  Purpose: OSINT & Target Intelligence for Bug Bounty Hunters
  Gathers: Emails · Subdomains · DNS Records · WHOIS · Technologies
           Social Profiles · Exposed Files · Metadata · Breached Data
           Employee Names · GitHub Repos · Security Headers · Shodan Info
  Legal  : For authorized security research ONLY
==============================================================================
"""

import subprocess
import sys
import os
import re
import json
import argparse
import shutil
import socket
import time
from datetime import datetime
from urllib.parse import urlparse, quote

# ─── Colors ───────────────────────────────────────────────────────────────────
class C:
    RESET   = "/033[0m"
    BOLD    = "/033[1m"
    RED     = "/033[91m"
    GREEN   = "/033[92m"
    YELLOW  = "/033[93m"
    CYAN    = "/033[96m"
    MAGENTA = "/033[95m"
    BLUE    = "/033[94m"
    WHITE   = "/033[97m"
    DIM     = "/033[2m"

# ─── Banner ───────────────────────────────────────────────────────────────────
def banner():
    print(f"""
{C.CYAN}{C.BOLD}
  ___  ____  ___  _   _ _____
 / _ // ___||_ _|| / | |_   _|
| | | /___ / | | |  /| | | |
| |_| |___) || | | |/  | | |
 /___/|____/|___||_| /_| |_|
{C.MAGENTA}
 _____ _   _ _____ _____  _     _     ___ ____  ___ _   _  ___  _____
|_   _| / | |_   _| ____|| |   | |   |_ _/ ___|/ _ / / | |/ _ /| ____|
  | | |  /| | | | |  _|  | |   | |    | | |  _| | | |  /| | | | |  _|
  | | | |/  | | | | |___ | |___| |___ | | |_| | |_| | |/  | |_| | |___
  |_| |_| /_| |_| |_____||_____|_____|___/____|/___/|_| /_|/___/|_____|
{C.YELLOW}
  ____    _  _____ _   _ _____ ____  _____ ____
 / ___|  / /|_   _| | | | ____|  _ /| ____|  _ //
| |  _  / _ / | | | |_| |  _| | |_) |  _| | |_) |
| |_| |/ ___ /| | |  _  | |___| _ < | |___|  _ <
 /____/_/   /_/_| |_| |_|_____|_| /_/_____|_| /_//
{C.RESET}
{C.DIM}  ─────────────────────────────────────────────────────────────────────
   fitijoe OSINT Intelligence Gatherer v1.0
   Author : fitijoe (MohamedSuleiman)
   GitHub : https://github.com/fitijoe
   Gathers: Emails · DNS · WHOIS · Subdomains · Technologies
            Social Profiles · GitHub · Exposed Files · Metadata
   Legal  : Authorized security research ONLY
  ─────────────────────────────────────────────────────────────────────{C.RESET}
""")

# ─── Helpers ──────────────────────────────────────────────────────────────────
def section(title):
    w = 70
    print(f"/n{C.CYAN}{C.BOLD}{'═'*w}/n  {title}/n{'═'*w}{C.RESET}/n")

def info(msg):   print(f"  {C.BLUE}[*]{C.RESET} {msg}")
def ok(msg):     print(f"  {C.GREEN}[+]{C.RESET} {msg}")
def warn(msg):   print(f"  {C.YELLOW}[!]{C.RESET} {msg}")
def found(msg):  print(f"  {C.MAGENTA}[FOUND]{C.RESET} {C.BOLD}{msg}{C.RESET}")
def skip(msg):   print(f"  {C.DIM}[SKIP] {msg}{C.RESET}")
def intel(msg):  print(f"  {C.CYAN}[INTEL]{C.RESET} {msg}")

def run(cmd, timeout=30):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return r.stdout + r.stderr
    except subprocess.TimeoutExpired:
        return "[TIMEOUT]"
    except Exception as e:
        return f"[ERROR] {e}"

def has(tool): return shutil.which(tool) is not None

def curl(url, timeout=15):
    return run(f"curl -skL --max-time {timeout} '{url}' -A 'Mozilla/5.0'", timeout+5)

def curl_code(url):
    return run(f"curl -sk -o /dev/null -w '%{{http_code}}' --max-time 10 '{url}'", 15).strip()

# ─── Tool Check ───────────────────────────────────────────────────────────────
def check_tools():
    section("TOOL CHECK")
    required = ["curl", "dig", "whois"]
    optional = ["subfinder", "amass", "theHarvester", "nmap",
                "exiftool", "whatweb", "wafw00f", "dnsx"]

    missing = [t for t in required if not has(t)]
    if missing:
        warn(f"Missing required: {', '.join(missing)}")
        warn(f"Fix: sudo apt install {' '.join(missing)} -y")
        sys.exit(1)
    ok(f"Required tools ready: {', '.join(required)}")

    found_opt, absent = [], []
    for t in optional:
        (found_opt if has(t) else absent).append(t)
    if found_opt:  ok(f"Optional found : {', '.join(found_opt)}")
    if absent:
        warn(f"Optional missing: {', '.join(absent)}")
        print(f"  {C.DIM}sudo apt install nmap exiftool whatweb wafw00f -y{C.RESET}")
        print(f"  {C.DIM}sudo apt install theharvester -y{C.RESET}")
        print(f"  {C.DIM}go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest{C.RESET}")
        print(f"  {C.DIM}go install github.com/projectdiscovery/amass/v4/...@master{C.RESET}")
        print(f"  {C.DIM}go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest{C.RESET}/n")
    return found_opt

# ─── MODULE 1: WHOIS & DNS ────────────────────────────────────────────────────
def module_whois_dns(domain):
    section("MODULE 1 — WHOIS & DNS INTELLIGENCE")
    data = {}

    # WHOIS
    info("Running WHOIS lookup...")
    whois_out = run(f"whois {domain} 2>/dev/null", 30)
    print(f"{C.DIM}{whois_out[:2000]}{C.RESET}")
    data['whois'] = whois_out

    # Extract key WHOIS fields
    for field, pat in [
        ('Registrar',        r'Registrar:/s*(.+)'),
        ('Registered',       r'Creation Date:/s*(.+)'),
        ('Expires',          r'Registry Expiry Date:/s*(.+)'),
        ('Registrant Org',   r'Registrant Organization:/s*(.+)'),
        ('Registrant Email', r'Registrant Email:/s*(.+)'),
        ('Name Servers',     r'Name Server:/s*(.+)'),
        ('Country',          r'Registrant Country:/s*(.+)'),
    ]:
        m = re.search(pat, whois_out, re.I)
        if m:
            val = m.group(1).strip()
            intel(f"{field}: {C.BOLD}{val}{C.RESET}")
            data[field.lower()] = val

    # DNS Records
    info("Enumerating DNS records...")
    record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA', 'SRV', 'CAA']
    dns_records = {}
    for rtype in record_types:
        result = run(f"dig +short {domain} {rtype} 2>/dev/null", 10)
        records = [r.strip() for r in result.splitlines() if r.strip()]
        if records:
            dns_records[rtype] = records
            ok(f"{rtype} records:")
            for r in records:
                print(f"      {C.CYAN}{r}{C.RESET}")

            # Interesting TXT records
            if rtype == 'TXT':
                for r in records:
                    if 'spf' in r.lower():
                        intel(f"SPF record found — reveals mail servers: {r}")
                    if 'dmarc' in r.lower():
                        intel(f"DMARC policy found: {r}")
                    if 'google' in r.lower():
                        intel(f"Google verification — company uses Google Workspace")
                    if 'ms=' in r.lower() or 'microsoft' in r.lower():
                        intel(f"Microsoft verification — company uses Office 365/Azure")
                    if 'stripe' in r.lower():
                        intel(f"Stripe verification — company processes payments with Stripe")
                    if 'atlassian' in r.lower():
                        intel(f"Atlassian verification — company uses Jira/Confluence")

    data['dns'] = dns_records

    # IP Address & Reverse DNS
    info("Resolving IP and reverse DNS...")
    try:
        ip = socket.gethostbyname(domain)
        ok(f"IP Address: {C.BOLD}{ip}{C.RESET}")
        data['ip'] = ip
        rev = run(f"dig +short -x {ip} 2>/dev/null", 10).strip()
        if rev:
            intel(f"Reverse DNS: {rev}")
    except:
        warn("Could not resolve IP")

    # Zone transfer attempt
    info("Attempting DNS zone transfer (AXFR)...")
    ns_records = dns_records.get('NS', [])
    for ns in ns_records[:3]:
        zt = run(f"dig axfr {domain} @{ns.rstrip('.')} 2>/dev/null", 15)
        if 'XFR size' in zt or (len(zt) > 200 and 'Transfer failed' not in zt):
            found(f"ZONE TRANSFER SUCCESSFUL from {ns}!")
            print(f"{C.RED}{zt[:2000]}{C.RESET}")
            data['zone_transfer'] = zt
        else:
            print(f"      {C.DIM}Zone transfer refused by {ns}{C.RESET}")

    return data

# ─── MODULE 2: SUBDOMAIN ENUMERATION ─────────────────────────────────────────
def module_subdomains(domain, opt):
    section("MODULE 2 — SUBDOMAIN ENUMERATION")
    all_subs = set()

    # Certificate Transparency (crt.sh) — no tools needed
    info("Querying crt.sh certificate transparency logs...")
    crt = curl(f"https://crt.sh/?q=%.{domain}&output=json", 20)
    try:
        crt_json = json.loads(crt)
        for entry in crt_json:
            name = entry.get('name_value', '')
            for sub in name.splitlines():
                sub = sub.strip().lstrip('*.')
                if domain in sub and sub != domain:
                    all_subs.add(sub)
        ok(f"crt.sh found {len(all_subs)} subdomains")
    except:
        warn("crt.sh query failed or returned no results")

    # HackerTarget
    info("Querying HackerTarget API...")
    ht = curl(f"https://api.hackertarget.com/hostsearch/?q={domain}", 15)
    for line in ht.splitlines():
        if ',' in line:
            sub = line.split(',')[0].strip()
            if domain in sub:
                all_subs.add(sub)
    ok(f"HackerTarget found additional subdomains (total: {len(all_subs)})")

    # AlienVault OTX
    info("Querying AlienVault OTX...")
    otx = curl(f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns", 20)
    try:
        otx_json = json.loads(otx)
        for entry in otx_json.get('passive_dns', []):
            hostname = entry.get('hostname', '')
            if domain in hostname:
                all_subs.add(hostname)
        ok(f"AlienVault OTX found additional subdomains (total: {len(all_subs)})")
    except:
        pass

    # RapidDNS
    info("Querying RapidDNS...")
    rdns = curl(f"https://rapiddns.io/subdomain/{domain}?full=1", 20)
    for match in re.findall(r'([a-zA-Z0-9/-/.]+/.' + re.escape(domain) + r')', rdns):
        all_subs.add(match)

    # Subfinder
    if 'subfinder' in opt:
        info("subfinder — passive subdomain enumeration...")
        sf = run(f"subfinder -d {domain} -silent 2>/dev/null", 120)
        for s in sf.splitlines():
            if s.strip() and domain in s:
                all_subs.add(s.strip())
        ok(f"subfinder complete (total: {len(all_subs)})")

    # Amass
    if 'amass' in opt:
        info("amass — deep subdomain enumeration...")
        am = run(f"amass enum -passive -d {domain} 2>/dev/null", 180)
        for s in am.splitlines():
            if domain in s:
                all_subs.add(s.strip())
        ok(f"amass complete (total: {len(all_subs)})")

    # theHarvester
    if 'theHarvester' in opt:
        info("theHarvester — multi-source OSINT gathering...")
        th = run(f"theHarvester -d {domain} -b all -l 100 2>/dev/null", 120)
        for match in re.findall(r'([a-zA-Z0-9/-/.]+/.' + re.escape(domain) + r')', th):
            all_subs.add(match)
        ok(f"theHarvester complete (total: {len(all_subs)})")

    # Print all found subdomains
    sub_list = sorted(all_subs)
    ok(f"/n  Total unique subdomains found: {C.BOLD}{len(sub_list)}{C.RESET}")
    for sub in sub_list[:50]:
        print(f"      {C.CYAN}{sub}{C.RESET}")
    if len(sub_list) > 50:
        print(f"      {C.DIM}... and {len(sub_list)-50} more (saved in report){C.RESET}")

    # Check live subdomains
    info("Checking which subdomains are live...")
    live_subs = []
    for sub in sub_list[:30]:
        code = curl_code(f"http://{sub}")
        if code not in ('000', ''):
            ok(f"LIVE [{code}]: {sub}")
            live_subs.append((sub, code))
        else:
            print(f"      {C.DIM}[dead] {sub}{C.RESET}")

    return {'subdomains': sub_list, 'live': live_subs}

# ─── MODULE 3: EMAIL & EMPLOYEE HARVESTING ───────────────────────────────────
def module_emails(domain, opt):
    section("MODULE 3 — EMAIL & EMPLOYEE INTELLIGENCE")
    emails = set()
    employees = []

    # Hunter.io (no key needed for basic)
    info("Querying Hunter.io for email patterns...")
    hunter = curl(f"https://api.hunter.io/v2/domain-search?domain={domain}&api_key=&limit=10", 15)
    try:
        h_json = json.loads(hunter)
        pattern = h_json.get('data', {}).get('pattern', '')
        if pattern:
            intel(f"Email pattern: {C.BOLD}{pattern}@{domain}{C.RESET}")
        for emp in h_json.get('data', {}).get('emails', []):
            email = emp.get('value', '')
            fname = emp.get('first_name', '')
            lname = emp.get('last_name', '')
            pos   = emp.get('position', '')
            if email:
                emails.add(email)
                found(f"Email: {email} — {fname} {lname} ({pos})")
                employees.append({'email': email, 'name': f"{fname} {lname}", 'position': pos})
    except:
        pass

    # Common email patterns to guess
    info("Generating common email format guesses...")
    common_patterns = [
        f"info@{domain}", f"admin@{domain}", f"contact@{domain}",
        f"support@{domain}", f"security@{domain}", f"abuse@{domain}",
        f"hello@{domain}", f"team@{domain}", f"careers@{domain}",
        f"hr@{domain}", f"sales@{domain}", f"dev@{domain}",
        f"it@{domain}", f"ceo@{domain}", f"cto@{domain}",
    ]
    for email in common_patterns:
        print(f"      {C.DIM}Guessed: {email}{C.RESET}")
        emails.add(email)

    # Google dorking for emails
    info("Google dork queries to find emails manually...")
    dorks = [
        f'site:{domain} "@{domain}"',
        f'site:{domain} "email" OR "contact"',
        f'"{domain}" email filetype:pdf',
        f'"{domain}" "mailto:"',
    ]
    print(f"/n  {C.YELLOW}Run these in Google to find more emails:{C.RESET}")
    for dork in dorks:
        print(f"      {C.CYAN}{dork}{C.RESET}")

    # LinkedIn employee search
    info("LinkedIn employee search queries...")
    print(f"/n  {C.YELLOW}Search LinkedIn for employees:{C.RESET}")
    li_queries = [
        f'site:linkedin.com/in "{domain.split(".")[0]}"',
        f'site:linkedin.com "{domain.split(".")[0].title()}" employee',
    ]
    for q in li_queries:
        print(f"      {C.CYAN}{q}{C.RESET}")

    # GitHub search for emails
    info("GitHub email search queries...")
    print(f"/n  {C.YELLOW}Search GitHub for emails:{C.RESET}")
    gh_queries = [
        f'https://github.com/search?q={domain}&type=commits',
        f'https://github.com/search?q="{domain}"&type=code',
    ]
    for q in gh_queries:
        print(f"      {C.CYAN}{q}{C.RESET}")

    ok(f"Total emails found/guessed: {len(emails)}")
    return {'emails': list(emails), 'employees': employees}

# ─── MODULE 4: TECHNOLOGY & INFRASTRUCTURE ────────────────────────────────────
def module_technology(domain, opt):
    section("MODULE 4 — TECHNOLOGY & INFRASTRUCTURE INTELLIGENCE")
    url = f"http://{domain}"
    tech_data = {}

    # WhatWeb
    if 'whatweb' in opt:
        info("whatweb — technology fingerprinting...")
        ww = run(f"whatweb -a 3 --colour=never {url} 2>/dev/null", 60)
        print(f"{C.DIM}{ww[:1500]}{C.RESET}")
        tech_data['whatweb'] = ww

        for tech, pat in [
            ('WordPress',   r'WordPress[/s/]+([/d.]+)'),
            ('Drupal',      r'Drupal[/s/]+([/d.]+)'),
            ('Joomla',      r'Joomla[/s/]+([/d.]+)'),
            ('PHP',         r'PHP[/s/]+([/d.]+)'),
            ('Apache',      r'Apache[/s/]+([/d.]+)'),
            ('nginx',       r'nginx[/s/]+([/d.]+)'),
            ('Cloudflare',  r'Cloudflare'),
            ('jQuery',      r'jQuery[/s/]+([/d.]+)'),
            ('React',       r'React'),
            ('Angular',     r'Angular'),
            ('Vue',         r'Vue/.js'),
            ('Laravel',     r'Laravel'),
            ('Django',      r'Django'),
            ('ASP.NET',     r'ASP/.NET'),
        ]:
            m = re.search(pat, ww, re.I)
            if m:
                ver = m.group(1) if m.lastindex else ''
                intel(f"Technology: {C.BOLD}{tech} {ver}{C.RESET}")

    # WAF Detection
    if 'wafw00f' in opt:
        info("wafw00f — WAF/CDN detection...")
        waf = run(f"wafw00f {url} 2>/dev/null", 30)
        print(f"{C.DIM}{waf[:500]}{C.RESET}")
        if 'is behind' in waf.lower():
            found(f"WAF/CDN detected — important for bug bounty!")

    # Shodan (no key — public info)
    info("Querying Shodan for infrastructure info...")
    try:
        ip_result = socket.gethostbyname(domain)
        shodan_url = f"https://internetdb.shodan.io/{ip_result}"
        shodan = curl(shodan_url, 15)
        try:
            s_json = json.loads(shodan)
            ports = s_json.get('ports', [])
            tags  = s_json.get('tags', [])
            cpes  = s_json.get('cpes', [])
            vulns = s_json.get('vulns', [])

            if ports:
                intel(f"Open ports (Shodan): {C.BOLD}{', '.join(map(str, ports))}{C.RESET}")
                tech_data['ports'] = ports
            if tags:
                intel(f"Tags: {', '.join(tags)}")
            if cpes:
                intel(f"Software detected: {', '.join(cpes[:5])}")
            if vulns:
                found(f"Known CVEs on this IP: {C.RED}{', '.join(vulns)}{C.RESET}")
                tech_data['cves'] = vulns
        except:
            pass
        intel(f"Full Shodan report: https://www.shodan.io/host/{ip_result}")
        tech_data['shodan_url'] = f"https://www.shodan.io/host/{ip_result}"
    except:
        warn("Could not resolve IP for Shodan lookup")

    # BuiltWith API (free tier)
    info("Querying BuiltWith for technology stack...")
    bw = curl(f"https://api.builtwith.com/free1/api.json?KEY=free&LOOKUP={domain}", 15)
    try:
        bw_json = json.loads(bw)
        techs = bw_json.get('Results', [{}])[0].get('Result', {}).get('Paths', [{}])[0].get('Technologies', [])
        if techs:
            ok(f"BuiltWith found {len(techs)} technologies:")
            for t in techs[:15]:
                name = t.get('Name', '')
                cat  = t.get('Categories', [''])[0] if t.get('Categories') else ''
                print(f"      {C.CYAN}{name}{C.RESET} {C.DIM}[{cat}]{C.RESET}")
    except:
        pass

    return tech_data

# ─── MODULE 5: GITHUB & CODE INTELLIGENCE ────────────────────────────────────
def module_github(domain, company_name):
    section("MODULE 5 — GITHUB & CODE INTELLIGENCE")
    company = company_name or domain.split('.')[0]

    # Search GitHub API (no auth needed for public)
    info(f"Searching GitHub for '{company}' repositories...")
    gh_repos = curl(f"https://api.github.com/search/repositories?q={company}&sort=updated&per_page=10", 15)
    try:
        gh_json = json.loads(gh_repos)
        repos = gh_json.get('items', [])
        if repos:
            ok(f"Found {len(repos)} public repositories:")
            for repo in repos[:10]:
                name    = repo.get('full_name', '')
                desc    = repo.get('description', '') or ''
                stars   = repo.get('stargazers_count', 0)
                lang    = repo.get('language', '') or ''
                updated = repo.get('updated_at', '')[:10]
                print(f"      {C.CYAN}{name}{C.RESET} ⭐{stars} [{lang}] {C.DIM}{desc[:50]}{C.RESET}")
    except:
        warn("GitHub API rate limited — try later or use a token")

    # Search for secrets in code
    info("GitHub dork queries to find exposed secrets...")
    secret_dorks = [
        f'"{domain}" password',
        f'"{domain}" secret',
        f'"{domain}" api_key',
        f'"{domain}" token',
        f'"{company}" AWS_SECRET',
        f'"{company}" db_password',
        f'"{company}" private_key',
        f'org:{company} filename:.env',
        f'org:{company} filename:config',
        f'org:{company} extension:sql',
        f'org:{company} extension:pem',
        f'org:{company} "BEGIN RSA PRIVATE KEY"',
    ]

    print(f"/n  {C.RED}Search these on GitHub for exposed secrets:{C.RESET}")
    for dork in secret_dorks:
        encoded = dork.replace(' ', '+')
        print(f"      {C.YELLOW}https://github.com/search?q={encoded}&type=code{C.RESET}")

    # Common GitHub usernames to check
    info("Checking common company GitHub profiles...")
    handles = [company, domain.split('.')[0], f"{company}-security", f"{company}dev"]
    for handle in handles:
        code = curl_code(f"https://github.com/{handle}")
        if code == '200':
            found(f"GitHub profile exists: https://github.com/{handle}")
        else:
            print(f"      {C.DIM}[{code}] https://github.com/{handle}{C.RESET}")

    return {'dorks': secret_dorks}

# ─── MODULE 6: EXPOSED FILES & GOOGLE DORKS ──────────────────────────────────
def module_dorks(domain):
    section("MODULE 6 — GOOGLE DORKS & EXPOSED FILES")

    dork_categories = {
        'Sensitive Files': [
            f'site:{domain} filetype:pdf',
            f'site:{domain} filetype:xls OR filetype:xlsx',
            f'site:{domain} filetype:doc OR filetype:docx',
            f'site:{domain} filetype:sql',
            f'site:{domain} filetype:xml',
            f'site:{domain} filetype:json',
            f'site:{domain} filetype:log',
            f'site:{domain} filetype:bak',
            f'site:{domain} filetype:conf',
            f'site:{domain} filetype:env',
        ],
        'Login & Admin Pages': [
            f'site:{domain} inurl:admin',
            f'site:{domain} inurl:login',
            f'site:{domain} inurl:dashboard',
            f'site:{domain} inurl:panel',
            f'site:{domain} inurl:portal',
            f'site:{domain} inurl:cpanel',
            f'site:{domain} inurl:wp-admin',
            f'site:{domain} inurl:phpmyadmin',
        ],
        'Exposed Credentials & Keys': [
            f'site:{domain} "password"',
            f'site:{domain} "api_key"',
            f'site:{domain} "secret_key"',
            f'site:{domain} "access_token"',
            f'site:{domain} "BEGIN RSA PRIVATE KEY"',
            f'site:{domain} intext:"index of" passwd',
            f'site:{domain} intext:"index of" .git',
        ],
        'Error Pages & Debug Info': [
            f'site:{domain} "sql syntax"',
            f'site:{domain} "Warning: mysql"',
            f'site:{domain} "Fatal error"',
            f'site:{domain} "Stack trace"',
            f'site:{domain} "Debug"',
            f'site:{domain} inurl:error',
            f'site:{domain} "Index of /"',
        ],
        'Subdomains & Hidden Pages': [
            f'site:*.{domain}',
            f'site:{domain} -www',
            f'site:{domain} inurl:test',
            f'site:{domain} inurl:dev',
            f'site:{domain} inurl:staging',
            f'site:{domain} inurl:beta',
            f'site:{domain} inurl:backup',
            f'site:{domain} inurl:old',
        ],
        'Wayback Machine': [
            f'https://web.archive.org/web/*/{domain}/*',
            f'https://web.archive.org/web/*/https://{domain}/api/*',
            f'https://web.archive.org/web/*/https://{domain}/admin/*',
        ]
    }

    for category, dorks in dork_categories.items():
        print(f"/n  {C.MAGENTA}{C.BOLD}► {category}{C.RESET}")
        for dork in dorks:
            encoded = quote(dork)
            if dork.startswith('http'):
                print(f"    {C.CYAN}{dork}{C.RESET}")
            else:
                print(f"    {C.CYAN}https://www.google.com/search?q={encoded}{C.RESET}")

    # Direct URL probes
    info("/nProbing for directly exposed sensitive files...")
    sensitive = [
        '/.git/HEAD', '/.env', '/robots.txt', '/sitemap.xml',
        '/.well-known/security.txt', '/security.txt',
        '/humans.txt', '/crossdomain.xml',
        '/phpinfo.php', '/info.php', '/server-status',
        '/backup.zip', '/backup.tar.gz', '/db.sql',
        '/swagger.json', '/openapi.json', '/api-docs',
        '/graphql', '/.DS_Store', '/web.config',
        '/adminer.php', '/phpmyadmin', '/admin',
        '/wp-login.php', '/xmlrpc.php',
    ]
    exposed = []
    for path in sensitive:
        code = curl_code(f"http://{domain}{path}")
        if code in ('200', '301', '302', '403'):
            found(f"[{code}] http://{domain}{path}")
            exposed.append(path)
        else:
            print(f"      {C.DIM}[{code}] {path}{C.RESET}")

    return {'dorks': dork_categories, 'exposed': exposed}

# ─── MODULE 7: BREACH & REPUTATION CHECK ─────────────────────────────────────
def module_breach(domain):
    section("MODULE 7 — BREACH & REPUTATION INTELLIGENCE")

    # Have I Been Pwned (domain search)
    info("Checking HaveIBeenPwned for domain breaches...")
    hibp = curl(f"https://haveibeenpwned.com/api/v3/breacheddomain/{domain}", 15)
    try:
        breaches = json.loads(hibp)
        if isinstance(breaches, list) and breaches:
            found(f"Domain found in {len(breaches)} data breach(es)!")
            for b in breaches[:10]:
                print(f"      {C.RED}● {b}{C.RESET}")
        else:
            ok("Domain not found in known breaches")
    except:
        intel(f"Check manually: https://haveibeenpwned.com/DomainSearch")

    # IntelX search
    info("Intelligence X search queries...")
    print(f"  {C.YELLOW}Search these for leaked data:{C.RESET}")
    intel_urls = [
        f"https://intelx.io/?s={domain}",
        f"https://dehashed.com/search?query={domain}",
        f"https://leakix.net/search?scope=leak&q={domain}",
        f"https://www.breachdirectory.org/",
    ]
    for u in intel_urls:
        print(f"      {C.CYAN}{u}{C.RESET}")

    # VirusTotal domain report
    info("VirusTotal domain reputation...")
    vt_url = f"https://www.virustotal.com/gui/domain/{domain}"
    intel(f"VirusTotal: {vt_url}")

    # URLScan.io
    info("URLScan.io scan history...")
    urlscan = curl(f"https://urlscan.io/api/v1/search/?q=domain:{domain}&size=5", 15)
    try:
        us_json = json.loads(urlscan)
        results = us_json.get('results', [])
        if results:
            ok(f"Found {len(results)} URLScan results:")
            for r in results[:5]:
                scan_url = r.get('result', '')
                task_url = r.get('task', {}).get('url', '')
                date     = r.get('task', {}).get('time', '')[:10]
                print(f"      {C.CYAN}{scan_url}{C.RESET} {C.DIM}({date}){C.RESET}")
    except:
        intel(f"URLScan: https://urlscan.io/search/#domain%3A{domain}")

    # SecurityTrails
    intel(f"SecurityTrails: https://securitytrails.com/domain/{domain}/dns")
    intel(f"DNSDumpster  : https://dnsdumpster.com/")
    intel(f"Censys       : https://search.censys.io/search?resource=hosts&q={domain}")
    intel(f"FOFA         : https://en.fofa.info/result?qbase64={domain}")

    return {}

# ─── MODULE 8: EXPLOIT & NEXT STEPS ──────────────────────────────────────────
def module_exploit_guidance(domain, all_data):
    section("MODULE 8 — EXPLOITATION GUIDANCE & NEXT STEPS")

    print(f"""
  {C.MAGENTA}{C.BOLD}▶ What to do with WHOIS data{C.RESET}
  {C.DIM}─────────────────────────────────────────────────────{C.RESET}
  {C.WHITE}Registrant email found?{C.RESET}
  $ theHarvester -d {domain} -b google,linkedin,twitter
  # Search email in HaveIBeenPwned for breached passwords
  # Search email on LinkedIn to find employees
  # Use email format to guess other employee emails

  {C.WHITE}Name servers found?{C.RESET}
  $ dig axfr {domain} @ns1.{domain}   # Attempt zone transfer
  # Zone transfer = get ALL subdomains instantly

  {C.MAGENTA}{C.BOLD}▶ What to do with Subdomains{C.RESET}
  {C.DIM}─────────────────────────────────────────────────────{C.RESET}
  {C.WHITE}Run the API tester on every live subdomain:{C.RESET}
  $ python3 fitijoe-api-tester.py -t http://api.{domain}
  $ python3 fitijoe-api-tester.py -t http://admin.{domain}
  $ python3 fitijoe-api-tester.py -t http://dev.{domain}

  {C.WHITE}Check for subdomain takeover:{C.RESET}
  $ subfinder -d {domain} -silent | httpx -silent | nuclei -t takeovers/

  {C.WHITE}Find old/forgotten subdomains in Wayback Machine:{C.RESET}
  $ curl -s "https://web.archive.org/cdx/search/cdx?url=*.{domain}&output=text&fl=original&collapse=urlkey"

  {C.MAGENTA}{C.BOLD}▶ What to do with Emails{C.RESET}
  {C.DIM}─────────────────────────────────────────────────────{C.RESET}
  {C.WHITE}Password spray with found email pattern:{C.RESET}
  # If pattern is firstname.lastname@{domain}:
  $ hydra -L emails.txt -P /usr/share/wordlists/rockyou.txt //
          -s 443 {domain} https-post-form //
          '/login:email=^USER^&password=^PASS^:incorrect'

  {C.WHITE}Check if emails are in breach databases:{C.RESET}
  # https://haveibeenpwned.com
  # https://dehashed.com
  # https://leakix.net

  {C.MAGENTA}{C.BOLD}▶ What to do with GitHub Intelligence{C.RESET}
  {C.DIM}─────────────────────────────────────────────────────{C.RESET}
  {C.WHITE}Scan GitHub repos for secrets:{C.RESET}
  $ git clone https://github.com/{domain.split('.')[0]}/REPO
  $ trufflehog git file://./REPO
  $ gitleaks detect --source ./REPO

  {C.WHITE}Search commit history for deleted secrets:{C.RESET}
  $ git log --all --full-history -- "*.env"
  $ git grep -i "password" $(git log --pretty=format:"%h")

  {C.MAGENTA}{C.BOLD}▶ What to do with Shodan/Port Data{C.RESET}
  {C.DIM}─────────────────────────────────────────────────────{C.RESET}
  {C.WHITE}Scan specific open ports:{C.RESET}
  $ nmap -sV -sC -p 21,22,25,80,443,3306,5432,6379,8080,8443,27017 {domain}
  # Port 6379 = Redis (often unauthenticated)
  # Port 27017 = MongoDB (often unauthenticated)
  # Port 3306 = MySQL (try default credentials)
  # Port 5432 = PostgreSQL

  {C.WHITE}Redis unauthenticated access:{C.RESET}
  $ redis-cli -h {domain} ping
  $ redis-cli -h {domain} info
  $ redis-cli -h {domain} keys *

  {C.MAGENTA}{C.BOLD}▶ Bug Bounty Report Tips{C.RESET}
  {C.DIM}─────────────────────────────────────────────────────{C.RESET}
  {C.WHITE}Best findings from OSINT:{C.RESET}
  ● Exposed .env file          → CRITICAL (immediate payout)
  ● Git repo exposed           → CRITICAL (source code theft)
  ● Subdomain takeover         → HIGH     ($500-$5000)
  ● Zone transfer enabled      → HIGH     (all subdomains exposed)
  ● Credentials in GitHub      → CRITICAL (account takeover)
  ● MongoDB/Redis open         → CRITICAL (data breach)
  ● Employee emails found      → INFO     (good for recon context)
  ● Old API endpoints          → MEDIUM   (may have vulnerabilities)
""")

# ─── REPORT ───────────────────────────────────────────────────────────────────
def save_report(domain, all_data, output_dir):
    os.makedirs(output_dir, exist_ok=True)
    ts = datetime.now().strftime('%Y%m%d_%H%M%S')
    path = os.path.join(output_dir, f"osint_report_{domain}_{ts}.txt")

    with open(path, 'w') as f:
        f.write("="*70 + "/n")
        f.write("  fitijoe OSINT Intelligence Report/n")
        f.write(f"  Target  : {domain}/n")
        f.write(f"  Date    : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}/n")
        f.write(f"  Author  : fitijoe (MohamedSuleiman)/n")
        f.write("="*70 + "/n/n")

        # WHOIS
        f.write("WHOIS INTELLIGENCE/n" + "─"*40 + "/n")
        for k in ['Registrar','Registered','Expires','Registrant Org','ip']:
            if k in all_data.get('whois', {}):
                f.write(f"  {k}: {all_data['whois'][k]}/n")
        f.write("/n")

        # Subdomains
        subs = all_data.get('subdomains', {}).get('subdomains', [])
        f.write(f"SUBDOMAINS ({len(subs)} found)/n" + "─"*40 + "/n")
        for s in subs:
            f.write(f"  {s}/n")
        f.write("/n")

        # Live subdomains
        live = all_data.get('subdomains', {}).get('live', [])
        f.write(f"LIVE SUBDOMAINS ({len(live)})/n" + "─"*40 + "/n")
        for s, code in live:
            f.write(f"  [{code}] {s}/n")
        f.write("/n")

        # Emails
        emails = all_data.get('emails', {}).get('emails', [])
        f.write(f"EMAILS ({len(emails)})/n" + "─"*40 + "/n")
        for e in emails:
            f.write(f"  {e}/n")
        f.write("/n")

        # Exposed files
        exposed = all_data.get('dorks', {}).get('exposed', [])
        f.write(f"EXPOSED FILES ({len(exposed)})/n" + "─"*40 + "/n")
        for e in exposed:
            f.write(f"  {e}/n")
        f.write("/n")

        # CVEs
        cves = all_data.get('tech', {}).get('cves', [])
        if cves:
            f.write(f"KNOWN CVEs ON IP/n" + "─"*40 + "/n")
            for c in cves:
                f.write(f"  {c}/n")
            f.write("/n")

        f.write("="*70 + "/n")
        f.write("  fitijoe (MohamedSuleiman) — github.com/fitijoe/n")
        f.write("="*70 + "/n")

    return path

# ─── MAIN ─────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description='fitijoe OSINT Intelligence Gatherer v1.0',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 fitijoe-osint.py -d google.com
  python3 fitijoe-osint.py -d tesla.com -c tesla
  python3 fitijoe-osint.py -d target.com --module dns
  python3 fitijoe-osint.py -d target.com --module emails
  python3 fitijoe-osint.py -d target.com --module all
        """
    )
    parser.add_argument('-d', '--domain',  required=True, help='Target domain (e.g. google.com)')
    parser.add_argument('-c', '--company', default='',    help='Company name (e.g. google)')
    parser.add_argument('--module', choices=['dns','subdomains','emails','tech','github','dorks','breach','all'],
                        default='all', help='Module to run (default: all)')
    parser.add_argument('-o', '--output',  default='./osint_reports', help='Output directory')
    args = parser.parse_args()

    banner()

    print(f"{C.YELLOW}{C.BOLD}  ⚠  LEGAL NOTICE{C.RESET}")
    print(f"  {C.DIM}This tool is for authorized security research ONLY.")
    print(f"  Only gather OSINT on targets you have permission to research.")
    print(f"  fitijoe (MohamedSuleiman) is not responsible for misuse.{C.RESET}/n")

    opt = check_tools()
    domain  = args.domain.lower().strip()
    company = args.company or domain.split('.')[0]

    print(f"/n  {C.BOLD}Target Domain{C.RESET} : {C.CYAN}{domain}{C.RESET}")
    print(f"  {C.BOLD}Company Name {C.RESET} : {C.CYAN}{company}{C.RESET}")
    print(f"  {C.BOLD}Module       {C.RESET} : {C.CYAN}{args.module}{C.RESET}")
    print(f"  {C.BOLD}Output       {C.RESET} : {C.CYAN}{args.output}{C.RESET}/n")

    all_data = {}

    if args.module in ('dns', 'all'):
        all_data['whois'] = module_whois_dns(domain)

    if args.module in ('subdomains', 'all'):
        all_data['subdomains'] = module_subdomains(domain, opt)

    if args.module in ('emails', 'all'):
        all_data['emails'] = module_emails(domain, opt)

    if args.module in ('tech', 'all'):
        all_data['tech'] = module_technology(domain, opt)

    if args.module in ('github', 'all'):
        all_data['github'] = module_github(domain, company)

    if args.module in ('dorks', 'all'):
        all_data['dorks'] = module_dorks(domain)

    if args.module in ('breach', 'all'):
        all_data['breach'] = module_breach(domain)

    if args.module == 'all':
        module_exploit_guidance(domain, all_data)

    report = save_report(domain, all_data, args.output)

    section("FINAL SUMMARY")
    subs  = len(all_data.get('subdomains', {}).get('subdomains', []))
    live  = len(all_data.get('subdomains', {}).get('live', []))
    emails = len(all_data.get('emails', {}).get('emails', []))
    exposed = len(all_data.get('dorks', {}).get('exposed', []))
    cves   = len(all_data.get('tech', {}).get('cves', []))

    ok(f"Subdomains found  : {subs}")
    ok(f"Live subdomains   : {live}")
    ok(f"Emails found      : {emails}")
    ok(f"Exposed files     : {exposed}")
    if cves: print(f"  {C.RED}[+]{C.RESET} Known CVEs on IP  : {C.BOLD}{cves}{C.RESET}")

    ok(f"Report saved to   : {C.CYAN}{report}{C.RESET}")
    print(f"/n  {C.DIM}OSINT complete — fitijoe (MohamedSuleiman) — {datetime.now().strftime('%H:%M:%S')}{C.RESET}/n")

if __name__ == '__main__':
    main()
