# OMEGA-CLI 🔍

> **108-command OSINT & Passive Recon Toolkit** — built for analysts, red teamers, and threat hunters.

```
 ██████╗ ███╗   ███╗███████╗ ██████╗  █████╗
██╔═══██╗████╗ ████║██╔════╝██╔════╝ ██╔══██╗
██║   ██║██╔████╔██║█████╗  ██║  ███╗███████║
██║   ██║██║╚██╔╝██║██╔══╝  ██║   ██║██╔══██║
╚██████╔╝██║ ╚═╝ ██║███████╗╚██████╔╝██║  ██║
 ╚═════╝ ╚═╝     ╚═╝╚══════╝ ╚═════╝ ╚═╝  ╚═╝
  OMEGA-CLI v1.8.0 — OSINT & Passive Recon Toolkit
```

[![Version](https://img.shields.io/badge/version-1.8.0-ff2d78?style=flat-square)](https://github.com/Ekoelogan/omega-cli/releases)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue?style=flat-square)](https://python.org)
[![License](https://img.shields.io/badge/license-MIT-green?style=flat-square)](LICENSE)
[![Commands](https://img.shields.io/badge/commands-108-purple?style=flat-square)](https://github.com/Ekoelogan/omega-cli)
[![Agents](https://img.shields.io/badge/AI%20agents-15-ff85b3?style=flat-square)](https://github.com/Ekoelogan/omega-cli)

---

## ⚡ Install

```bash
pip install pipx  # or: brew install pipx
pipx install git+https://github.com/Ekoelogan/omega-cli.git
```

Or clone and install locally:

```bash
git clone https://github.com/Ekoelogan/omega-cli.git
cd omega-cli
pipx install .
```

---

## 🚀 Quick Start

```bash
# Full passive recon on a target
omega auto target.com

# DNS + WHOIS + SSL + headers chain
omega chain run quick-recon --target target.com

# Full passive chain
omega chain run full-passive --target target.com

# Live parallel recon dashboard
omega scan target.com
```

---

## 📦 Module Reference

### Core Recon
| Command | Description |
|---|---|
| `omega dns <target>` | DNS record enumeration (A, MX, TXT, NS, SOA, AAAA) |
| `omega whois <target>` | WHOIS + registrar + org + abuse contact |
| `omega ssl <target>` | TLS cert chain, expiry, SAN, CT logs |
| `omega headers <target>` | HTTP security headers analysis |
| `omega sub <target>` | Subdomain enumeration (passive) |
| `omega reverseip <ip>` | Reverse IP — co-hosted domains |
| `omega geo <target>` | IP geolocation + ASN |
| `omega tech <target>` | Technology fingerprinting |
| `omega ports <target>` | Port scan (common ports) |

### Threat Intelligence
| Command | Description |
|---|---|
| `omega shodan <target>` | Shodan host + CVE lookup |
| `omega virustotal <target>` | VirusTotal URL/IP/hash scan |
| `omega threatintel <target>` | Multi-source threat intel |
| `omega threatfeed [list\|fetch\|search]` | Feodo/URLhaus/ThreatFox/SSLBL/Bazaar feeds |
| `omega vuln2 <cve-or-keyword>` | NVD CPE + EPSS exploit probability + CISA KEV + PoC |
| `omega cve <target>` | CVE lookup and mapping |
| `omega exfil <target>` | DNS tunnel entropy, DGA detection, C2 analysis |
| `omega malware <target>` | Malware indicator analysis |

### Identity & Social
| Command | Description |
|---|---|
| `omega harvest <domain>` | Email + username harvesting |
| `omega breach <email>` | Data breach check (HIBP) |
| `omega username <handle>` | Username search across platforms |
| `omega socmint <username>` | 25-platform social media OSINT + profile aggregation |
| `omega persona` | Fictitious identity generator (red team) |
| `omega phoneosint <number>` | Phone carrier, line type, CNAM, spam score |
| `omega identity <target>` | Identity correlation engine |

### Network & Infrastructure
| Command | Description |
|---|---|
| `omega ipdossier <ip>` | PTR + ASN + BGP + Shodan + 8-DNSBL + risk score |
| `omega asnrecon <target>` | ASN + BGP prefix enumeration |
| `omega webcrawl <target>` | Smart crawler: forms, JS endpoints, secrets, sitemap |
| `omega apiosint <target>` | Swagger/OpenAPI discovery, GraphQL introspection |
| `omega corscheck <target>` | CORS misconfiguration scanner |
| `omega dorks <target>` | Google/Bing OSINT dork generator |
| `omega wayback <target>` | Wayback Machine archive analysis |
| `omega network <target>` | Network topology mapping |

### Cloud & Code
| Command | Description |
|---|---|
| `omega cloud2 <target>` | S3/GCS/Azure blob enum + GitHub Actions discovery |
| `omega cloudrecon <target>` | Cloud infrastructure footprint |
| `omega buckets <target>` | Open bucket finder |
| `omega gitrecon <user>` | GitHub org/user repo intelligence |
| `omega codetrace <user>` | Commit timezone/geography attribution |
| `omega supply <target>` | Software supply chain analysis |
| `omega secrets <target>` | Secret/credential scanner |

### Documents & Files
| Command | Description |
|---|---|
| `omega imgosint <image>` | EXIF, GPS coords, reverse search, steg hints |
| `omega docosint <file>` | PDF/Office metadata, embedded URLs, secret scan |

### Blockchain
| Command | Description |
|---|---|
| `omega cryptoosint <address>` | BTC/ETH tx history, mixing detection, OFAC sanctions |
| `omega crypto <target>` | Cryptocurrency OSINT |

### Intelligence & Reporting
| Command | Description |
|---|---|
| `omega autocorr <target>` | Cross-module IOC correlation engine |
| `omega briefing <target>` | HTML/Markdown intel briefing from all findings |
| `omega reportgen <target>` | Master HTML/Markdown/PDF report (all modules) |
| `omega riskcore <target>` | Weighted CVSS-like risk scoring engine |
| `omega executive <target>` | Executive summary report |
| `omega stix <target>` | STIX 2.1 threat intelligence export |
| `omega timeline3d <target>` | Interactive D3.js temporal event graph |

### Automation
| Command | Description |
|---|---|
| `omega auto <target>` | Full recon chain — chains ALL modules |
| `omega scan <target>` | Live parallel TUI dashboard |
| `omega chain run <name> --target <T>` | Named recon chains |
| `omega monitor <target>` | Continuous change monitoring |
| `omega watcher <target>` | File/domain change watcher |

### Built-in Chains
```bash
omega chain run quick-recon    --target example.com   # DNS + WHOIS + SSL + headers
omega chain run full-passive   --target example.com   # subdomain + wayback + cert + tech
omega chain run threat-hunt    --target example.com   # auto → IOC → ATT&CK mapping
omega chain run brand-monitor  --target example.com   # typo + phish + breach + social
omega chain run red-team       --target example.com   # git + wordlist + fuzz + creds
```

---

## 🤖 AI Agent Framework

15 specialist AI agents with shared memory, task planning, and autonomous workflows.

### Quick Start

```bash
omega agents                                    # List all 15 agents
omega agent recon-agent example.com            # Run single agent
omega autopilot example.com --task bug-bounty  # Multi-agent workflow
omega chat                                      # Interactive AI chat mode
omega memory --stats                            # Query stored findings
omega memory --search "critical"                # Search findings
```

### Agent Categories

| Agent | Category | Capabilities |
|-------|----------|-------------|
| `recon-agent` | Information Gathering | WHOIS, DNS, subdomains, certs, IP intel, tech fingerprint |
| `web-agent` | Web Application | Headers, CORS, JS secrets, crawling, spider |
| `vuln-agent` | Vulnerability | CVE lookup, vuln scanning, risk scoring, port analysis |
| `cloud-agent` | Cloud Security | S3 buckets, Azure blobs, GCP storage, cloud recon |
| `social-agent` | Identity & Social | Username search, email OSINT, social profiles |
| `exploit-agent` | Exploitation | Exploit search, payload generation, red team ops |
| `wifi-agent` | Wireless | WiFi analysis, AP discovery, signal recon |
| `password-agent` | Credentials | Wordlist generation, breach checks, credential auditing |
| `forensics-agent` | Digital Forensics | Document analysis, image metadata, IOC extraction |
| `reverse-agent` | Reverse Engineering | Firmware analysis, binary inspection, code review |
| `post-agent` | Post-Exploitation | Exfil detection, C2 analysis, lateral movement |
| `privacy-agent` | Anonymity & Privacy | Tor checks, OPSEC analysis, dark web presence |
| `crypto-agent` | Crypto & Stego | Blockchain tracing, cryptocurrency OSINT, stego detection |
| `ai-security-agent` | AI Security | ML model auditing, AI-assisted threat detection |
| `report-agent` | Reporting | PDF/HTML reports, executive summaries, timeline views |

### Architecture

```
User Request → Planner → Router → [Agent1, Agent2, ...] → Shared Memory → Report
                                        ↓
                                  Agent handoff (recon→vuln→exploit chain)
```

- **Shared Memory**: SQLite-backed findings store — any agent can query
- **Task Planning**: Automatic decomposition of complex tasks
- **Agent Handoff**: Agents recommend follow-up agents based on findings
- **Parallel Execution**: Independent agents run concurrently

---

## ⚙️ Configuration

```bash
omega config set shodan_api_key      YOUR_KEY
omega config set hibp_api_key        YOUR_KEY
omega config set virustotal_api_key  YOUR_KEY
omega config set nvd_api_key         YOUR_KEY
omega config set github_token        YOUR_TOKEN
omega config set abuseipdb_key       YOUR_KEY
omega config set etherscan_key       YOUR_KEY
```

Or set environment variables:
```bash
export SHODAN_API_KEY=...
export HIBP_API_KEY=...
export GITHUB_TOKEN=...
```

---

## 🗂 Output

All findings auto-saved as JSON to `~/.omega/reports/`:
```
~/.omega/reports/
  dns_example_com.json
  ssl_example_com.json
  vuln2_CVE-2021-44228.json
  socmint_johndoe.json
  ...
```

Generate a master report from all findings:
```bash
omega reportgen example.com --format html --open
omega reportgen example.com --format pdf
```

---

## 📋 Requirements

- Python 3.10+
- pipx (recommended) or pip
- Optional: `weasyprint` for PDF reports (`pipx inject omega-cli weasyprint`)

---

## ⚠️ Legal Notice

omega-cli is intended for **authorized security research, penetration testing, and OSINT** on systems you own or have explicit permission to test. Unauthorized use against third-party systems may violate computer fraud laws. Use responsibly.

---

## 📄 License

MIT License — see [LICENSE](LICENSE)

---

*Built with ❤️ and autonomy by [Ekoelogan](https://github.com/Ekoelogan)*
