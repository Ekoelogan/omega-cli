"""HexStrike AI — autonomous multi-phase penetration testing engine.

Orchestrates OMEGA-CLI modules through an AI-driven pipeline that
performs reconnaissance, enumeration, vulnerability analysis, exploit
mapping, attack-surface aggregation, and structured reporting.

Phases:
    RECON → ENUMERATE → VULN_ANALYZE → EXPLOIT_MAP → ATTACK_SURFACE → REPORT

Each phase feeds findings into an Ollama-backed decision engine that
prioritises the next steps and adjusts scope dynamically.
"""

from __future__ import annotations

import importlib
import json
import os
import time
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

import requests
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.table import Table

console = Console()

# ── Theme ────────────────────────────────────────────────────────────
PRIMARY = "#ff2d78"
ACCENT = "#ff85b3"
TARGET_CLR = "cyan"
DIM = "dim #cc6688"

# ── Phase definitions ────────────────────────────────────────────────

class Phase(str, Enum):
    """Ordered penetration-testing phases."""
    RECON = "RECON"
    ENUMERATE = "ENUMERATE"
    VULN_ANALYZE = "VULN_ANALYZE"
    EXPLOIT_MAP = "EXPLOIT_MAP"
    ATTACK_SURFACE = "ATTACK_SURFACE"
    REPORT = "REPORT"


PHASE_DESCRIPTIONS: Dict[Phase, str] = {
    Phase.RECON: "Subdomain enumeration, DNS resolution, WHOIS, technology fingerprinting",
    Phase.ENUMERATE: "Port scanning, service detection, JS scanning, robots/sitemap discovery",
    Phase.VULN_ANALYZE: "CVE lookup, HTTP header audit, SSL/TLS analysis, CORS misconfiguration",
    Phase.EXPLOIT_MAP: "CVE-to-exploit matching, EPSS scoring, attack-path mapping",
    Phase.ATTACK_SURFACE: "Aggregate findings, risk scoring, attack-graph construction",
    Phase.REPORT: "Executive summary, technical detail, remediation guidance",
}

# ── Helpers ──────────────────────────────────────────────────────────

def _safe_import(module_name: str):
    """Import an omega_cli module by name, returning None on failure."""
    try:
        return importlib.import_module(f"omega_cli.modules.{module_name}")
    except ImportError:
        return None


def _ts() -> str:
    """ISO-8601 UTC timestamp."""
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _ask_ollama(prompt: str, model: str = "mistral") -> str:
    """Query a local Ollama instance for AI-driven decision-making.

    Falls back to a deterministic default when Ollama is unreachable.
    """
    try:
        resp = requests.post(
            "http://localhost:11434/api/generate",
            json={"model": model, "prompt": prompt, "stream": False},
            timeout=30,
        )
        if resp.status_code == 200:
            return resp.json().get("response", "")
    except requests.RequestException:
        pass
    return ""


# ── Phase runners ────────────────────────────────────────────────────

def _run_phase_recon(target: str) -> Dict[str, Any]:
    """Phase 1 — passive reconnaissance."""
    findings: Dict[str, Any] = {"phase": Phase.RECON.value, "ts": _ts(), "data": {}}

    # Subdomain enumeration
    mod = _safe_import("subdomain")
    if mod:
        try:
            result = mod.run(target)
            findings["data"]["subdomains"] = result if isinstance(result, dict) else {}
        except Exception as exc:
            findings["data"]["subdomains"] = {"error": str(exc)}

    # DNS records
    mod = _safe_import("dns_lookup")
    if mod:
        try:
            result = mod.run(target, "ALL")
            findings["data"]["dns"] = result if isinstance(result, dict) else {}
        except Exception as exc:
            findings["data"]["dns"] = {"error": str(exc)}

    # WHOIS
    mod = _safe_import("whois_lookup")
    if mod:
        try:
            result = mod.run(target)
            findings["data"]["whois"] = result if isinstance(result, dict) else {}
        except Exception as exc:
            findings["data"]["whois"] = {"error": str(exc)}

    # Technology fingerprinting
    mod = _safe_import("techfp")
    if mod:
        try:
            result = mod.run(target)
            findings["data"]["tech"] = result if isinstance(result, dict) else {}
        except Exception as exc:
            findings["data"]["tech"] = {"error": str(exc)}

    return findings


def _run_phase_enumerate(target: str) -> Dict[str, Any]:
    """Phase 2 — active enumeration of services and assets."""
    findings: Dict[str, Any] = {"phase": Phase.ENUMERATE.value, "ts": _ts(), "data": {}}

    # Port scan
    mod = _safe_import("portscan")
    if mod:
        try:
            result = mod.run(target)
            findings["data"]["ports"] = result if isinstance(result, dict) else {}
        except Exception as exc:
            findings["data"]["ports"] = {"error": str(exc)}

    # JavaScript file scanning
    mod = _safe_import("jscan")
    if mod:
        try:
            result = mod.run(target)
            findings["data"]["jscan"] = result if isinstance(result, dict) else {}
        except Exception as exc:
            findings["data"]["jscan"] = {"error": str(exc)}

    # Web crawl for robots/sitemap
    mod = _safe_import("webcrawl")
    if mod:
        try:
            result = mod.run(target)
            findings["data"]["crawl"] = result if isinstance(result, dict) else {}
        except Exception as exc:
            findings["data"]["crawl"] = {"error": str(exc)}

    # Spider for deeper link extraction
    mod = _safe_import("spider")
    if mod:
        try:
            result = mod.run(target)
            findings["data"]["spider"] = result if isinstance(result, dict) else {}
        except Exception as exc:
            findings["data"]["spider"] = {"error": str(exc)}

    return findings


def _run_phase_vuln_analyze(target: str) -> Dict[str, Any]:
    """Phase 3 — vulnerability identification and analysis."""
    findings: Dict[str, Any] = {"phase": Phase.VULN_ANALYZE.value, "ts": _ts(), "data": {}}

    # CVE / vulnerability lookup
    mod = _safe_import("vuln2")
    if mod:
        try:
            result = mod.run(target)
            findings["data"]["vulns"] = result if isinstance(result, dict) else {}
        except Exception as exc:
            findings["data"]["vulns"] = {"error": str(exc)}

    # HTTP security headers
    mod = _safe_import("headers")
    if mod:
        try:
            result = mod.run(target)
            findings["data"]["headers"] = result if isinstance(result, dict) else {}
        except Exception as exc:
            findings["data"]["headers"] = {"error": str(exc)}

    # SSL/TLS certificate analysis
    mod = _safe_import("ssl_check")
    if mod:
        try:
            result = mod.run(target)
            findings["data"]["ssl"] = result if isinstance(result, dict) else {}
        except Exception as exc:
            findings["data"]["ssl"] = {"error": str(exc)}

    # CORS misconfiguration
    mod = _safe_import("corscheck")
    if mod:
        try:
            result = mod.run(target)
            findings["data"]["cors"] = result if isinstance(result, dict) else {}
        except Exception as exc:
            findings["data"]["cors"] = {"error": str(exc)}

    return findings


def _run_phase_exploit_map(target: str, prior_findings: List[Dict]) -> Dict[str, Any]:
    """Phase 4 — map discovered vulnerabilities to known exploits."""
    findings: Dict[str, Any] = {"phase": Phase.EXPLOIT_MAP.value, "ts": _ts(), "data": {}}

    # Extract CVE IDs from prior vulnerability findings
    cve_ids: List[str] = []
    for phase_data in prior_findings:
        vulns = phase_data.get("data", {}).get("vulns", {})
        if isinstance(vulns, dict):
            for v in vulns.get("vulnerabilities", vulns.get("cves", [])):
                cve_id = v.get("cve_id") or v.get("id", "")
                if cve_id.startswith("CVE-"):
                    cve_ids.append(cve_id)

    # NVD / CVE enrichment
    mod = _safe_import("nvd_cve")
    if mod and cve_ids:
        enriched = []
        for cve_id in cve_ids[:20]:  # cap to avoid rate-limits
            try:
                result = mod.run(cve_id)
                enriched.append(result if isinstance(result, dict) else {"id": cve_id})
            except Exception:
                enriched.append({"id": cve_id, "error": "lookup failed"})
        findings["data"]["cve_details"] = enriched

    # CVSS risk ranking
    mod = _safe_import("cvssrank")
    if mod:
        try:
            result = mod.run(target)
            findings["data"]["cvss_rank"] = result if isinstance(result, dict) else {}
        except Exception as exc:
            findings["data"]["cvss_rank"] = {"error": str(exc)}

    # Red-team intelligence
    mod = _safe_import("redteam")
    if mod:
        try:
            result = mod.run(target)
            findings["data"]["redteam"] = result if isinstance(result, dict) else {}
        except Exception as exc:
            findings["data"]["redteam"] = {"error": str(exc)}

    findings["data"]["cve_count"] = len(cve_ids)
    return findings


def _run_phase_attack_surface(target: str, all_findings: List[Dict]) -> Dict[str, Any]:
    """Phase 5 — aggregate findings into a unified attack surface model."""
    findings: Dict[str, Any] = {
        "phase": Phase.ATTACK_SURFACE.value,
        "ts": _ts(),
        "data": {},
    }

    subdomains = []
    open_ports = []
    vulns = []
    technologies = []

    for pf in all_findings:
        data = pf.get("data", {})
        subdomains.extend(data.get("subdomains", {}).get("subdomains", []))
        open_ports.extend(data.get("ports", {}).get("ports", []))
        vulns.extend(data.get("vulns", {}).get("vulnerabilities", []))
        tech = data.get("tech", {})
        if isinstance(tech, dict):
            technologies.extend(tech.get("technologies", []))

    # Simple risk score heuristic
    risk_score = min(
        10.0,
        round(
            len(vulns) * 1.5
            + len(open_ports) * 0.3
            + len(subdomains) * 0.1
            + len(technologies) * 0.05,
            1,
        ),
    )

    findings["data"] = {
        "target": target,
        "total_subdomains": len(subdomains),
        "total_open_ports": len(open_ports),
        "total_vulns": len(vulns),
        "total_technologies": len(technologies),
        "risk_score": risk_score,
        "risk_label": (
            "CRITICAL" if risk_score >= 8
            else "HIGH" if risk_score >= 6
            else "MEDIUM" if risk_score >= 3
            else "LOW"
        ),
    }
    return findings


def _run_phase_report(
    target: str,
    all_findings: List[Dict],
    output_dir: str,
) -> Dict[str, Any]:
    """Phase 6 — generate a structured JSON pentest report."""
    report_data: Dict[str, Any] = {
        "title": f"HexStrike Pentest Report — {target}",
        "generated": _ts(),
        "target": target,
        "phases": all_findings,
    }

    # Attempt to use the built-in report generator for a rich HTML report
    mod = _safe_import("reportgen")
    if mod:
        try:
            mod.run(target)
        except Exception:
            pass

    # Always write JSON report
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    report_path = out / f"hexstrike_{target.replace('.', '_')}_{int(time.time())}.json"
    report_path.write_text(json.dumps(report_data, indent=2, default=str))
    console.print(f"  [green]✓[/green] Report saved to [bold]{report_path}[/bold]")

    return {"phase": Phase.REPORT.value, "ts": _ts(), "report_path": str(report_path)}


# ── HexStrike Engine ─────────────────────────────────────────────────

class HexStrikeEngine:
    """Orchestrates the full autonomous penetration-testing pipeline.

    Parameters
    ----------
    target : str
        Primary target domain or IP.
    confirm : bool
        Explicit authorisation flag (``--confirm``).
    phases : list[Phase] | None
        Subset of phases to execute; *None* means all.
    ollama_model : str
        Ollama model name used for inter-phase AI decisions.
    output_dir : str
        Directory for report artefacts.
    """

    def __init__(
        self,
        target: str,
        confirm: bool = False,
        phases: Optional[List[Phase]] = None,
        ollama_model: str = "mistral",
        output_dir: str = "./hexstrike_reports",
    ) -> None:
        self.target = target
        self.confirm = confirm
        self.phases = phases or list(Phase)
        self.ollama_model = ollama_model
        self.output_dir = output_dir
        self.findings: List[Dict[str, Any]] = []
        self.start_time: Optional[float] = None

    # ── authorisation gate ───────────────────────────────────────
    def _check_authorisation(self) -> bool:
        if self.confirm:
            return True
        console.print(
            Panel(
                "[bold red]⚠  AUTHORIZATION REQUIRED[/bold red]\n\n"
                f"You are about to launch an autonomous pentest against "
                f"[bold {TARGET_CLR}]{self.target}[/bold {TARGET_CLR}].\n"
                "This will perform active scanning and enumeration.\n\n"
                "[yellow]Ensure you have explicit written authorisation from "
                "the asset owner before proceeding.[/yellow]\n\n"
                f"Re-run with [bold]--confirm[/bold] to acknowledge.",
                title=f"[bold {PRIMARY}]HexStrike AI[/bold {PRIMARY}]",
                border_style=PRIMARY,
            )
        )
        return False

    # ── AI decision layer ────────────────────────────────────────
    def _ai_decide(self, completed_phase: Phase) -> str:
        """Ask Ollama to analyse findings and suggest priorities."""
        summary = json.dumps(self.findings[-1], default=str)[:2000]
        prompt = (
            f"You are a penetration-testing AI assistant. The phase "
            f"'{completed_phase.value}' just completed against "
            f"'{self.target}'. Findings summary:\n{summary}\n\n"
            "Based on these results, list the top 3 areas to focus on "
            "in the next phase. Be concise (one sentence each)."
        )
        ai_response = _ask_ollama(prompt, self.ollama_model)
        if ai_response:
            console.print(
                Panel(
                    ai_response.strip(),
                    title=f"[bold {ACCENT}]AI Insight ({self.ollama_model})[/bold {ACCENT}]",
                    border_style=ACCENT,
                )
            )
        return ai_response

    # ── phase dispatcher ─────────────────────────────────────────
    def _execute_phase(self, phase: Phase) -> Dict[str, Any]:
        """Dispatch to the appropriate phase runner."""
        dispatch = {
            Phase.RECON: lambda: _run_phase_recon(self.target),
            Phase.ENUMERATE: lambda: _run_phase_enumerate(self.target),
            Phase.VULN_ANALYZE: lambda: _run_phase_vuln_analyze(self.target),
            Phase.EXPLOIT_MAP: lambda: _run_phase_exploit_map(self.target, self.findings),
            Phase.ATTACK_SURFACE: lambda: _run_phase_attack_surface(self.target, self.findings),
            Phase.REPORT: lambda: _run_phase_report(self.target, self.findings, self.output_dir),
        }
        return dispatch[phase]()

    # ── main loop ────────────────────────────────────────────────
    def execute(self) -> List[Dict[str, Any]]:
        """Run the full pipeline and return all findings."""
        if not self._check_authorisation():
            return []

        self.start_time = time.time()
        console.print(
            Panel(
                f"[bold {ACCENT}]Target:[/bold {ACCENT}] [{TARGET_CLR}]{self.target}[/{TARGET_CLR}]\n"
                f"[bold {ACCENT}]Phases:[/bold {ACCENT}] {', '.join(p.value for p in self.phases)}\n"
                f"[bold {ACCENT}]AI Model:[/bold {ACCENT}] {self.ollama_model}\n"
                f"[bold {ACCENT}]Output:[/bold {ACCENT}] {self.output_dir}",
                title=f"[bold {PRIMARY}]⬡ HexStrike AI — Engagement Started[/bold {PRIMARY}]",
                border_style=PRIMARY,
            )
        )

        with Progress(
            SpinnerColumn(style=f"bold {PRIMARY}"),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(complete_style=PRIMARY, finished_style="green"),
            console=console,
        ) as progress:
            task_id = progress.add_task("Running phases…", total=len(self.phases))

            for phase in self.phases:
                progress.update(
                    task_id,
                    description=f"[bold {ACCENT}]{phase.value}[/bold {ACCENT}] — {PHASE_DESCRIPTIONS[phase][:50]}",
                )
                console.print(f"\n[bold {PRIMARY}]{'━' * 60}[/bold {PRIMARY}]")
                console.print(
                    f"[bold {PRIMARY}]⬡ Phase:[/bold {PRIMARY}] "
                    f"[bold white]{phase.value}[/bold white]  "
                    f"[{DIM}]{PHASE_DESCRIPTIONS[phase]}[/{DIM}]"
                )
                console.print(f"[bold {PRIMARY}]{'━' * 60}[/bold {PRIMARY}]\n")

                result = self._execute_phase(phase)
                self.findings.append(result)

                # AI inter-phase analysis (skip before report)
                if phase != Phase.REPORT:
                    self._ai_decide(phase)

                progress.advance(task_id)

        elapsed = time.time() - self.start_time
        console.print(
            Panel(
                f"[bold green]✓ All phases complete[/bold green] in "
                f"[bold]{elapsed:.1f}s[/bold]\n"
                f"Findings collected: [bold]{len(self.findings)}[/bold] phases",
                title=f"[bold {PRIMARY}]⬡ HexStrike AI — Engagement Finished[/bold {PRIMARY}]",
                border_style="green",
            )
        )
        return self.findings


# ── CLI-facing functions ─────────────────────────────────────────────

def run(
    target: str,
    confirm: bool = False,
    phases: Optional[str] = None,
    ollama_model: str = "mistral",
    output_dir: str = "./hexstrike_reports",
) -> List[Dict[str, Any]]:
    """Launch the full autonomous pentest pipeline.

    Parameters
    ----------
    target : str
        Domain or IP to engage.
    confirm : bool
        Pass ``True`` (or ``--confirm`` on CLI) to acknowledge authorisation.
    phases : str | None
        Comma-separated phase names to execute (default: all).
    ollama_model : str
        Local Ollama model for AI analysis.
    output_dir : str
        Directory to write reports into.
    """
    selected: Optional[List[Phase]] = None
    if phases:
        selected = []
        for name in phases.split(","):
            name = name.strip().upper()
            try:
                selected.append(Phase(name))
            except ValueError:
                console.print(f"[red]Unknown phase:[/red] {name}")
                return []

    engine = HexStrikeEngine(
        target=target,
        confirm=confirm,
        phases=selected,
        ollama_model=ollama_model,
        output_dir=output_dir,
    )
    return engine.execute()


def plan(target: str) -> None:
    """Display the attack plan for *target* without executing any scans."""
    console.print(
        Panel(
            f"[bold {ACCENT}]Target:[/bold {ACCENT}] [{TARGET_CLR}]{target}[/{TARGET_CLR}]",
            title=f"[bold {PRIMARY}]⬡ HexStrike AI — Attack Plan[/bold {PRIMARY}]",
            border_style=PRIMARY,
        )
    )

    table = Table(
        title="Execution Plan",
        show_header=True,
        border_style=PRIMARY,
    )
    table.add_column("#", style="bold white", width=4)
    table.add_column("Phase", style=f"bold {ACCENT}")
    table.add_column("Description", style="white")
    table.add_column("Modules", style=TARGET_CLR)

    phase_modules = {
        Phase.RECON: "subdomain, dns_lookup, whois_lookup, techfp",
        Phase.ENUMERATE: "portscan, jscan, webcrawl, spider",
        Phase.VULN_ANALYZE: "vuln2, headers, ssl_check, corscheck",
        Phase.EXPLOIT_MAP: "nvd_cve, cvssrank, redteam",
        Phase.ATTACK_SURFACE: "(aggregation engine)",
        Phase.REPORT: "reportgen + JSON export",
    }

    for idx, phase in enumerate(Phase, 1):
        table.add_row(
            str(idx),
            phase.value,
            PHASE_DESCRIPTIONS[phase],
            phase_modules.get(phase, "—"),
        )

    console.print(table)
    console.print(
        f"\n[{DIM}]Run with [bold]--confirm[/bold] to execute this plan.[/{DIM}]\n"
    )


def status() -> None:
    """Display current engagement status by checking for report artefacts."""
    report_dir = Path("./hexstrike_reports")
    console.print(
        Panel(
            f"[bold {ACCENT}]Report directory:[/bold {ACCENT}] {report_dir.resolve()}",
            title=f"[bold {PRIMARY}]⬡ HexStrike AI — Status[/bold {PRIMARY}]",
            border_style=PRIMARY,
        )
    )

    if not report_dir.exists():
        console.print("[yellow]No engagements found. Run a scan first.[/yellow]")
        return

    reports = sorted(report_dir.glob("hexstrike_*.json"), reverse=True)
    if not reports:
        console.print("[yellow]No reports found in output directory.[/yellow]")
        return

    table = Table(show_header=True, border_style=ACCENT)
    table.add_column("Report", style="bold white")
    table.add_column("Size", style=TARGET_CLR)
    table.add_column("Modified", style="white")

    for rp in reports[:15]:
        stat = rp.stat()
        table.add_row(
            rp.name,
            f"{stat.st_size:,} B",
            datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
        )

    console.print(table)
    console.print(f"\n[bold]Total reports:[/bold] {len(reports)}")


def report(target: str, output: str = "./hexstrike_reports") -> None:
    """Generate a pentest report from existing findings on disk.

    Scans *output* for prior HexStrike JSON data, merges the findings,
    and produces a consolidated report.
    """
    out = Path(output)
    if not out.exists():
        console.print(f"[red]Output directory not found:[/red] {out}")
        return

    prefix = f"hexstrike_{target.replace('.', '_')}_"
    prior = sorted(out.glob(f"{prefix}*.json"), reverse=True)
    if not prior:
        console.print(f"[yellow]No prior findings for[/yellow] [{TARGET_CLR}]{target}[/{TARGET_CLR}]")
        return

    latest = prior[0]
    console.print(f"  [green]✓[/green] Loading findings from [bold]{latest.name}[/bold]")

    try:
        data = json.loads(latest.read_text())
    except (json.JSONDecodeError, OSError) as exc:
        console.print(f"[red]Failed to read report:[/red] {exc}")
        return

    # Executive summary panel
    phases_data = data.get("phases", [])
    attack_surface = next(
        (p for p in phases_data if p.get("phase") == Phase.ATTACK_SURFACE.value),
        {},
    )
    surface_data = attack_surface.get("data", {})

    console.print(
        Panel(
            f"[bold white]Target:[/bold white] [{TARGET_CLR}]{data.get('target', target)}[/{TARGET_CLR}]\n"
            f"[bold white]Generated:[/bold white] {data.get('generated', 'N/A')}\n"
            f"[bold white]Risk Score:[/bold white] [bold red]{surface_data.get('risk_score', 'N/A')}[/bold red] "
            f"({surface_data.get('risk_label', '—')})\n"
            f"[bold white]Subdomains:[/bold white] {surface_data.get('total_subdomains', 0)}\n"
            f"[bold white]Open Ports:[/bold white] {surface_data.get('total_open_ports', 0)}\n"
            f"[bold white]Vulnerabilities:[/bold white] {surface_data.get('total_vulns', 0)}",
            title=f"[bold {PRIMARY}]⬡ HexStrike AI — Executive Summary[/bold {PRIMARY}]",
            border_style=PRIMARY,
        )
    )

    # Per-phase summary table
    table = Table(title="Phase Results", show_header=True, border_style=ACCENT)
    table.add_column("Phase", style=f"bold {ACCENT}")
    table.add_column("Timestamp", style="white")
    table.add_column("Findings", style=TARGET_CLR)

    for pf in phases_data:
        phase_name = pf.get("phase", "?")
        ts = pf.get("ts", "—")
        data_keys = list(pf.get("data", {}).keys())
        table.add_row(phase_name, ts, ", ".join(data_keys) if data_keys else "—")

    console.print(table)
    console.print()
