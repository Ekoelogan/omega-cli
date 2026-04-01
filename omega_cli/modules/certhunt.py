"""certhunt.py — Certificate transparency pivot: org-wide cert inventory, SAN expansion, shadow IT."""
from __future__ import annotations
import json, re, time
from pathlib import Path
from collections import defaultdict
from typing import Optional
import urllib.request, urllib.error

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

UA = "Mozilla/5.0 (compatible; OmegaCLI/1.9.0)"

INTERESTING_KEYWORDS = [
    "dev", "staging", "stage", "test", "uat", "qa", "preprod", "sandbox",
    "admin", "portal", "internal", "intranet", "corp", "vpn", "remote",
    "api", "backend", "db", "database", "sql", "mongo", "redis", "elastic",
    "jenkins", "gitlab", "git", "ci", "cd", "jira", "confluence",
    "grafana", "kibana", "prometheus", "monitor", "metrics",
    "mail", "smtp", "email", "webmail", "exchange", "owa",
    "backup", "old", "legacy", "archive", "bak",
    "cloud", "aws", "azure", "gcp", "k8s", "docker",
    "secret", "vault", "key", "auth", "login", "sso",
    "pay", "payment", "checkout", "billing", "invoice",
    "beta", "alpha", "new", "v2", "v3",
]


def _get_json(url: str, timeout: int = 15) -> Optional[list | dict]:
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read().decode())
    except Exception:
        return None


def _crtsh(domain: str, wildcard: bool = True) -> list[dict]:
    q = f"%.{domain}" if wildcard else domain
    import urllib.parse
    url = f"https://crt.sh/?q={urllib.parse.quote(q)}&output=json"
    data = _get_json(url)
    if not data or not isinstance(data, list):
        return []
    return data


def _certspotter(domain: str) -> list[dict]:
    url = f"https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names"
    data = _get_json(url)
    if not data or not isinstance(data, list):
        return []
    return data


def _extract_names(cert: dict) -> list[str]:
    """Extract all domain names from a crt.sh cert entry."""
    names = set()
    for field in ("name_value", "common_name"):
        val = cert.get(field, "")
        for n in re.split(r"[\n,\s]+", val):
            n = n.strip().lstrip("*.")
            if n and "." in n:
                names.add(n.lower())
    return list(names)


def _extract_names_certspotter(cert: dict) -> list[str]:
    names = set()
    for n in cert.get("dns_names", []):
        n = n.strip().lstrip("*.")
        if n and "." in n:
            names.add(n.lower())
    return list(names)


def _is_interesting(subdomain: str) -> tuple[bool, str]:
    for kw in INTERESTING_KEYWORDS:
        if kw in subdomain.split(".")[0].lower():
            return True, kw
    return False, ""


def run(domain: str, deep: bool = False, export: str = ""):
    console.print(BANNER, style="bold magenta")
    console.print(Panel(f"🔐  Certificate Transparency Hunt — {domain}", style="bold cyan"))

    results = {
        "domain":      domain,
        "all_names":   [],
        "issuers":     {},
        "interesting": [],
        "shadow_it":   [],
        "cert_count":  0,
    }

    # crt.sh
    console.print("[bold]Querying crt.sh...[/bold]")
    crtsh_certs = _crtsh(domain)
    console.print(f"  [cyan]{len(crtsh_certs)} certificates found[/cyan]")

    all_names: set[str] = set()
    issuer_counts: dict[str, int] = defaultdict(int)

    for cert in crtsh_certs:
        names = _extract_names(cert)
        all_names.update(names)
        issuer = cert.get("issuer_name", "")
        org_match = re.search(r"O=([^,]+)", issuer)
        if org_match:
            issuer_counts[org_match.group(1).strip()] += 1

    # certspotter (additional coverage)
    if deep:
        console.print("[bold]Querying certspotter...[/bold]")
        sp_certs = _certspotter(domain)
        console.print(f"  [cyan]{len(sp_certs)} certificates from certspotter[/cyan]")
        for cert in sp_certs:
            all_names.update(_extract_names_certspotter(cert))

    # Filter to domain scope
    base_parts = domain.split(".")
    base = ".".join(base_parts[-2:])
    in_scope = sorted({n for n in all_names if n.endswith(base) or n == base})
    out_of_scope = sorted({n for n in all_names if not n.endswith(base) and n != base})

    results["all_names"]  = in_scope
    results["cert_count"] = len(crtsh_certs)
    results["issuers"]    = dict(sorted(issuer_counts.items(), key=lambda x: -x[1]))

    console.print(f"\n[bold]Unique domains/subdomains:[/bold] {len(in_scope)} in-scope")

    # Interesting / shadow IT
    interesting = []
    for name in in_scope:
        is_int, kw = _is_interesting(name)
        if is_int:
            interesting.append({"name": name, "keyword": kw})

    results["interesting"] = interesting
    results["shadow_it"]   = [i for i in interesting if any(k in i["keyword"] for k in
                               ["dev","staging","test","internal","jenkins","gitlab","admin","db","backup"])]

    # Display
    t = Table(title=f"📋 All Subdomains from CT Logs ({len(in_scope)})", box=box.SIMPLE if box else None)
    t.add_column("Subdomain", style="cyan")
    t.add_column("Interesting", style="yellow")
    for name in in_scope[:60]:
        is_int, kw = _is_interesting(name)
        t.add_row(name, f"[yellow]{kw}[/yellow]" if is_int else "")
    if len(in_scope) > 60:
        t.add_row(f"[dim]... and {len(in_scope)-60} more[/dim]", "")
    console.print(t)

    if interesting:
        console.print(f"\n[bold yellow]⚠ Interesting subdomains ({len(interesting)}):[/bold yellow]")
        for i in interesting[:20]:
            shadow = " [red](shadow IT?)[/red]" if i in results["shadow_it"] else ""
            console.print(f"  [yellow]{i['name']}[/yellow] [dim]← {i['keyword']}[/dim]{shadow}")

    # Issuers
    if issuer_counts:
        console.print(f"\n[bold]Certificate Issuers:[/bold]")
        for issuer, count in list(results["issuers"].items())[:8]:
            console.print(f"  {count:3d}×  [dim]{issuer[:60]}[/dim]")

    console.print(f"\n[bold]Summary:[/bold] {len(crtsh_certs)} certs | {len(in_scope)} unique subdomains | "
                  f"[yellow]{len(interesting)} interesting[/yellow] | "
                  f"[red]{len(results['shadow_it'])} shadow IT[/red]")

    out_dir = Path.home() / ".omega" / "reports"
    out_dir.mkdir(parents=True, exist_ok=True)
    safe = re.sub(r"[^\w.-]", "_", domain)
    out_path = Path(export) if export else out_dir / f"certhunt_{safe}.json"
    out_path.write_text(json.dumps(results, indent=2))
    console.print(f"[dim]Saved → {out_path}[/dim]")
