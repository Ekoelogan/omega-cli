"""mailsec.py — SPF/DKIM/DMARC analysis, mail server fingerprint, spoofability score."""
from __future__ import annotations
import json, re, socket
from pathlib import Path
from typing import Optional

try:
    import dns.resolver, dns.exception
    HAS_DNS = True
except ImportError:
    HAS_DNS = False

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich import box
    console = Console()
except ImportError:
    class Console:
        def print(self, *a, **kw): print(*a)
    console = Console()
    Table = Panel = box = None

BANNER = r"""
██████╗ ███╗   ███╗███████╗ ██████╗  █████╗ 
 ██╔═══██╗████╗ ████║██╔════╝██╔════╝ ██╔══██╗
 ██║   ██║██╔████╔██║█████╗  ██║  ███╗███████║
 ██║   ██║██║╚██╔╝██║██╔══╝  ██║   ██║██╔══██║
 ╚██████╔╝██║ ╚═╝ ██║███████╗╚██████╔╝██║  ██║
  ╚═════╝ ╚═╝     ╚═╝╚══════╝ ╚═════╝ ╚═╝  ╚═╝
  OMEGA-CLI v1.9.0 — OSINT & Passive Recon Toolkit
"""

COMMON_DKIM_SELECTORS = [
    "default", "google", "mail", "smtp", "dkim", "k1", "k2", "s1", "s2",
    "selector1", "selector2", "mimecast", "sendgrid", "mailgun", "ses",
    "proofpoint", "mcsv1", "everlytickey1", "everlytickey2", "cm",
    "mandrill", "sparkpost", "postmark", "zoho", "yandex",
]


def _query(name: str, rtype: str, lifetime: float = 5.0) -> list[str]:
    if not HAS_DNS:
        return []
    resolver = dns.resolver.Resolver()
    resolver.lifetime = lifetime
    try:
        return [str(r) for r in resolver.resolve(name, rtype)]
    except Exception:
        return []


def _spf_analyze(domain: str) -> dict:
    records = [r for r in _query(domain, "TXT") if "v=spf1" in r.lower()]
    if not records:
        return {"found": False, "record": None, "mechanisms": [], "all_tag": None,
                "includes": [], "risk": "HIGH", "risk_reason": "No SPF record — spoofing trivially possible"}

    record = records[0]
    mechanisms = re.findall(r"[+\-~?]?(?:ip4|ip6|a|mx|include|exists|redirect|all)(?::[^\s]+)?", record, re.I)
    includes   = re.findall(r"include:([^\s]+)", record, re.I)
    all_tag    = re.search(r"([+\-~?])all", record)
    all_val    = all_tag.group(1) if all_tag else None

    risk, risk_reason = "LOW", "SPF properly configured"
    if all_val == "+":
        risk, risk_reason = "CRITICAL", "+all means ANYONE can send as this domain"
    elif all_val == "~":
        risk, risk_reason = "MEDIUM",   "~all (SoftFail) allows spoofing with reduced spam score"
    elif all_val == "?":
        risk, risk_reason = "HIGH",     "?all (Neutral) provides no protection"
    elif all_val is None:
        risk, risk_reason = "HIGH",     "Missing -all or ~all — spoofing possible"

    return {"found": True, "record": record, "mechanisms": mechanisms,
            "includes": includes, "all_tag": all_val, "risk": risk, "risk_reason": risk_reason}


def _dmarc_analyze(domain: str) -> dict:
    records = _query(f"_dmarc.{domain}", "TXT")
    dmarc_records = [r for r in records if "v=DMARC1" in r]
    if not dmarc_records:
        return {"found": False, "record": None, "policy": None, "pct": None,
                "rua": None, "ruf": None, "risk": "HIGH",
                "risk_reason": "No DMARC record — spoofed emails won't be rejected"}

    record = dmarc_records[0]
    policy  = re.search(r"p=(\w+)",   record, re.I)
    sp      = re.search(r"sp=(\w+)",  record, re.I)
    pct     = re.search(r"pct=(\d+)", record, re.I)
    rua     = re.search(r"rua=([^;]+)", record, re.I)
    ruf     = re.search(r"ruf=([^;]+)", record, re.I)
    adkim   = re.search(r"adkim=([rs])", record, re.I)
    aspf    = re.search(r"aspf=([rs])",  record, re.I)

    p   = policy.group(1).lower() if policy else "none"
    pct_val = int(pct.group(1)) if pct else 100

    risk, risk_reason = "LOW", "DMARC enforced"
    if p == "none":
        risk, risk_reason = "HIGH", "p=none — monitoring only, no enforcement"
    elif p == "quarantine" and pct_val < 100:
        risk, risk_reason = "MEDIUM", f"p=quarantine but pct={pct_val}% — partial enforcement"
    elif p == "quarantine":
        risk, risk_reason = "MEDIUM", "p=quarantine — moves to spam but not rejected"

    return {
        "found": True, "record": record,
        "policy": p, "subdomain_policy": sp.group(1) if sp else p,
        "pct": pct_val, "rua": rua.group(1).strip() if rua else None,
        "ruf": ruf.group(1).strip() if ruf else None,
        "adkim": adkim.group(1) if adkim else "r",
        "aspf":  aspf.group(1) if aspf else "r",
        "risk": risk, "risk_reason": risk_reason,
    }


def _dkim_hunt(domain: str, selectors: list[str]) -> list[dict]:
    found = []
    for sel in selectors:
        name = f"{sel}._domainkey.{domain}"
        records = _query(name, "TXT")
        for r in records:
            if "v=DKIM1" in r or "p=" in r:
                key_match = re.search(r"p=([A-Za-z0-9+/=]+)", r)
                key_len = 0
                if key_match and key_match.group(1):
                    import base64
                    try:
                        key_len = len(base64.b64decode(key_match.group(1))) * 8
                    except Exception:
                        key_len = len(key_match.group(1)) * 6  # approx
                found.append({
                    "selector": sel,
                    "record":   r[:200],
                    "key_bits": key_len,
                    "weak":     key_len > 0 and key_len < 1024,
                })
    return found


def _mx_fingerprint(domain: str) -> list[dict]:
    mx_records = _query(domain, "MX")
    providers = []
    for mx in mx_records:
        mx_lower = mx.lower()
        if "google" in mx_lower or "googlemail" in mx_lower:
            provider = "Google Workspace"
        elif "outlook" in mx_lower or "microsoft" in mx_lower or "protection.outlook" in mx_lower:
            provider = "Microsoft 365 / Exchange Online"
        elif "mimecast" in mx_lower:
            provider = "Mimecast"
        elif "proofpoint" in mx_lower:
            provider = "Proofpoint"
        elif "barracuda" in mx_lower:
            provider = "Barracuda"
        elif "amazon" in mx_lower or "amazonaws" in mx_lower:
            provider = "Amazon SES"
        elif "mailgun" in mx_lower:
            provider = "Mailgun"
        elif "sendgrid" in mx_lower:
            provider = "SendGrid"
        elif "pphosted" in mx_lower:
            provider = "Proofpoint Hosted"
        elif "zoho" in mx_lower:
            provider = "Zoho Mail"
        elif "fastmail" in mx_lower:
            provider = "Fastmail"
        else:
            provider = "Unknown/Self-hosted"
        providers.append({"mx": mx.strip(), "provider": provider})
    return providers


def _catch_all_test(domain: str) -> Optional[bool]:
    """Check if domain accepts mail to random addresses (catch-all)."""
    random_addr = f"omega-test-{__import__('random').randint(100000,999999)}@{domain}"
    mxs = _query(domain, "MX")
    if not mxs:
        return None
    mx_host = re.sub(r"^\d+\s+", "", mxs[0]).rstrip(".")
    try:
        mx_ip = socket.gethostbyname(mx_host)
        import smtplib
        with smtplib.SMTP(mx_ip, 25, timeout=8) as smtp:
            smtp.ehlo("omega-cli.sh")
            code, _ = smtp.rcpt(random_addr)
            return code == 250
    except Exception:
        return None


def run(domain: str, check_catchall: bool = False, dkim_selectors: str = "", export: str = ""):
    console.print(BANNER, style="bold magenta")
    console.print(Panel(f"📧  Mail Security — {domain}", style="bold cyan"))

    results: dict = {"domain": domain, "spf": {}, "dmarc": {}, "dkim": [], "mx": [], "spoofability": 0}

    # SPF
    console.print("\n[bold]SPF[/bold]")
    spf = _spf_analyze(domain)
    results["spf"] = spf
    risk_color = {"CRITICAL": "red", "HIGH": "orange3", "MEDIUM": "yellow", "LOW": "green"}.get(spf["risk"], "white")
    if spf["found"]:
        console.print(f"  Record: [dim]{spf['record'][:100]}[/dim]")
        console.print(f"  -all tag: [cyan]{spf.get('all_tag') or 'missing'}[/cyan]")
        console.print(f"  Includes: {', '.join(spf['includes'][:5]) or 'none'}")
    else:
        console.print("  [red]No SPF record found[/red]")
    console.print(f"  Risk: [{risk_color}]{spf['risk']} — {spf['risk_reason']}[/{risk_color}]")

    # DMARC
    console.print("\n[bold]DMARC[/bold]")
    dmarc = _dmarc_analyze(domain)
    results["dmarc"] = dmarc
    risk_color = {"CRITICAL": "red", "HIGH": "orange3", "MEDIUM": "yellow", "LOW": "green"}.get(dmarc["risk"], "white")
    if dmarc["found"]:
        console.print(f"  Policy: [cyan]{dmarc['policy']}[/cyan]  pct={dmarc['pct']}%  subdomain={dmarc['subdomain_policy']}")
        console.print(f"  adkim={dmarc['adkim']}  aspf={dmarc['aspf']}")
        if dmarc["rua"]: console.print(f"  Reports (rua): {dmarc['rua'][:80]}")
    else:
        console.print("  [red]No DMARC record found[/red]")
    console.print(f"  Risk: [{risk_color}]{dmarc['risk']} — {dmarc['risk_reason']}[/{risk_color}]")

    # DKIM
    console.print("\n[bold]DKIM (selector hunt)[/bold]")
    selectors = dkim_selectors.split(",") if dkim_selectors else COMMON_DKIM_SELECTORS
    dkim_found = _dkim_hunt(domain, selectors)
    results["dkim"] = dkim_found
    if dkim_found:
        for d in dkim_found:
            weak = " [red](WEAK KEY < 1024-bit)[/red]" if d["weak"] else ""
            console.print(f"  ✓ selector=[cyan]{d['selector']}[/cyan] key={d['key_bits']}bit{weak}")
    else:
        console.print("  [dim]No DKIM selectors found[/dim]")

    # MX fingerprint
    console.print("\n[bold]MX / Mail Provider[/bold]")
    mx = _mx_fingerprint(domain)
    results["mx"] = mx
    for m in mx:
        console.print(f"  {m['mx']:50s} → [cyan]{m['provider']}[/cyan]")
    if not mx:
        console.print("  [dim]No MX records[/dim]")

    # Catch-all
    if check_catchall:
        console.print("\n[bold]Catch-all test...[/bold]")
        ca = _catch_all_test(domain)
        results["catch_all"] = ca
        if ca is True:
            console.print("  [yellow]⚠ Catch-all ENABLED — accepts mail to any address (user enum prevented)[/yellow]")
        elif ca is False:
            console.print("  [green]✓ Not catch-all[/green]")
        else:
            console.print("  [dim]Could not test (SMTP blocked or no MX)[/dim]")

    # Spoofability score
    score = 0
    if not spf["found"]:             score += 40
    elif spf["all_tag"] == "+":      score += 40
    elif spf["all_tag"] == "~":      score += 20
    elif spf["all_tag"] == "?":      score += 30
    elif spf["all_tag"] is None:     score += 30
    if not dmarc["found"]:           score += 40
    elif dmarc["policy"] == "none":  score += 30
    elif dmarc["policy"] == "quarantine" and dmarc["pct"] < 100: score += 15
    for d in dkim_found:
        if d["weak"]: score += 10
    score = min(100, score)
    scolor = "red" if score >= 70 else "orange3" if score >= 40 else "yellow" if score >= 20 else "green"
    results["spoofability"] = score
    spoofable = score >= 50
    console.print(f"\n[bold]Spoofability Score:[/bold] [{scolor}]{score}/100[/{scolor}] "
                  f"— {'[red bold]HIGH RISK: Domain can likely be spoofed[/red bold]' if spoofable else '[green]Low spoofing risk[/green]'}")

    out_dir = Path.home() / ".omega" / "reports"
    out_dir.mkdir(parents=True, exist_ok=True)
    safe = re.sub(r"[^\w.-]", "_", domain)
    out_path = Path(export) if export else out_dir / f"mailsec_{safe}.json"
    out_path.write_text(json.dumps(results, indent=2))
    console.print(f"[dim]Saved → {out_path}[/dim]")
