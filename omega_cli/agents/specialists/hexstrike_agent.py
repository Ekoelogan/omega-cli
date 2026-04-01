"""HexStrikeAgent — autonomous offensive security framework for pentest automation."""
from __future__ import annotations

from typing import Any

from omega_cli.agents.base_agent import BaseAgent, Finding, Severity


class HexStrikeAgent(BaseAgent):
    name = "hexstrike-agent"
    description = "HexStrike AI — autonomous offensive security framework for pentest automation"
    category = "offensive"
    capabilities = [
        "pentest_automation",
        "exploit_mapping",
        "attack_surface",
        "vuln_chain",
        "ai_decision",
    ]
    tools = ["recon", "scan", "ports", "cve", "vuln2", "cors", "headers", "ssl", "fuzz"]

    # ── engagement phases ──────────────────────────────────────────────
    PHASES = [
        ("reconnaissance", ["recon"], "Passive footprinting and target profiling"),
        ("service_discovery", ["ports", "scan"], "Port scanning and service enumeration"),
        ("web_surface", ["headers", "cors", "ssl"], "Web security posture analysis"),
        ("vuln_assessment", ["vuln2", "cve"], "Vulnerability identification and CVE mapping"),
        ("fuzzing", ["fuzz"], "Input fuzzing for edge-case vulnerabilities"),
        ("correlation", [], "Cross-phase finding correlation and attack path mapping"),
    ]

    def plan(self) -> list[str]:
        return [
            f"Phase {i + 1}/{len(self.PHASES)} — {label}: {desc}"
            for i, (label, _tools, desc) in enumerate(self.PHASES)
        ]

    # ── execute ────────────────────────────────────────────────────────
    def execute(self) -> dict[str, Any]:
        data: dict[str, Any] = {}
        completed_tools: set[str] = set()

        for phase_name, phase_tools, _desc in self.PHASES:
            self.log(f"[HexStrike] Entering phase: {phase_name}")
            phase_results: dict[str, Any] = {}

            for tool_name in phase_tools:
                if tool_name in completed_tools:
                    continue
                self.log(f"  Running {tool_name}...")
                try:
                    result = self.executor.run_omega(tool_name, self.target)
                    if result.success and result.data:
                        phase_results[tool_name] = result.data
                    elif result.success:
                        phase_results[tool_name] = {"output": result.output[:3000]}
                    else:
                        self.log(f"  {tool_name} failed: {result.error}")
                except Exception as e:
                    self.log(f"  {tool_name} error: {e}")
                completed_tools.add(tool_name)

            if phase_results:
                data[phase_name] = phase_results

        return data

    # ── analyze ────────────────────────────────────────────────────────
    def analyze(self, data: dict[str, Any]) -> list[Finding]:
        self._analyze_recon(data.get("reconnaissance", {}))
        self._analyze_services(data.get("service_discovery", {}))
        self._analyze_web(data.get("web_surface", {}))
        self._analyze_vulns(data.get("vuln_assessment", {}))
        self._analyze_fuzzing(data.get("fuzzing", {}))
        self._correlate_findings()
        return self.findings

    # -- reconnaissance -------------------------------------------------
    def _analyze_recon(self, phase: dict[str, Any]) -> None:
        recon = phase.get("recon", {})
        if not isinstance(recon, dict):
            return

        subs = recon.get("subdomains", [])
        if isinstance(subs, list) and len(subs) > 30:
            self.add_finding(
                f"Extensive Attack Surface ({len(subs)} subdomains)",
                Severity.MEDIUM,
                f"Enumerated {len(subs)} subdomains — large perimeter increases "
                "likelihood of forgotten or unpatched assets.",
                evidence=", ".join(subs[:15]),
                recommendation="Audit all subdomains. Decommission staging, dev, and legacy hosts.",
                tags=["attack-surface", "subdomains", "recon"],
            )

        if recon.get("cloud_providers") or "amazonaws" in str(recon).lower():
            self.add_finding(
                "Cloud Infrastructure Detected",
                Severity.INFO,
                "Target infrastructure includes cloud-hosted assets that may expose "
                "storage buckets, metadata endpoints, or misconfigured IAM policies.",
                evidence=str(recon.get("cloud_providers", ""))[:300],
                recommendation="Enumerate cloud resources for public buckets and metadata SSRF.",
                tags=["cloud", "infrastructure", "recon"],
            )

    # -- service discovery ----------------------------------------------
    def _analyze_services(self, phase: dict[str, Any]) -> None:
        ports_data = phase.get("ports", {})
        scan_data = phase.get("scan", {})
        combined = {**ports_data, **scan_data} if isinstance(ports_data, dict) and isinstance(scan_data, dict) else ports_data or scan_data

        if not isinstance(combined, dict):
            return

        open_ports = combined.get("open_ports", combined.get("ports", []))
        if isinstance(open_ports, list):
            high_risk = [p for p in open_ports if self._is_high_risk_port(p)]
            if high_risk:
                self.add_finding(
                    f"High-Risk Services Exposed ({len(high_risk)} ports)",
                    Severity.HIGH,
                    "Sensitive services are directly reachable from the network. "
                    "Database, admin, and management ports should not be publicly accessible.",
                    evidence=f"High-risk ports: {', '.join(str(p) for p in high_risk)}",
                    recommendation="Restrict access via firewall rules. Move admin services behind VPN.",
                    tags=["ports", "exposure", "network"],
                )
            if open_ports:
                self.add_finding(
                    f"Open Ports Enumerated ({len(open_ports)})",
                    Severity.INFO,
                    f"Discovered {len(open_ports)} open ports on {self.target}.",
                    evidence=f"Ports: {', '.join(str(p) for p in open_ports[:20])}",
                    tags=["ports", "enumeration"],
                )

        services = combined.get("services", [])
        if isinstance(services, list):
            for svc in services:
                svc_str = str(svc).lower()
                if any(old in svc_str for old in ["apache/2.2", "nginx/1.0", "iis/6", "openssh/5"]):
                    self.add_finding(
                        "Outdated Service Version Detected",
                        Severity.HIGH,
                        f"A service running an outdated version was detected: {svc_str[:200]}. "
                        "Older versions often have publicly known exploits.",
                        evidence=svc_str[:300],
                        recommendation="Upgrade to the latest stable release immediately.",
                        tags=["outdated", "service", "cve-risk"],
                    )

    # -- web surface ----------------------------------------------------
    def _analyze_web(self, phase: dict[str, Any]) -> None:
        # Headers
        headers = phase.get("headers", {})
        if isinstance(headers, dict):
            missing = self._check_missing_headers(headers)
            if len(missing) >= 4:
                self.add_finding(
                    f"Weak HTTP Security Posture ({len(missing)} headers missing)",
                    Severity.MEDIUM,
                    f"Missing security headers: {', '.join(missing)}. "
                    "This weakens defenses against XSS, clickjacking, and MIME sniffing.",
                    recommendation="Configure all recommended security headers on the web server.",
                    tags=["headers", "web-security", "hardening"],
                )

        # CORS
        cors = phase.get("cors", {})
        if isinstance(cors, dict) and (cors.get("vulnerable") or cors.get("misconfigured")):
            self.add_finding(
                "CORS Misconfiguration — Origin Reflection",
                Severity.HIGH,
                "The server reflects arbitrary origins or allows credentials with wildcard, "
                "enabling cross-origin data theft via a malicious page.",
                evidence=str(cors)[:500],
                recommendation="Whitelist specific trusted origins. Never reflect the Origin header blindly.",
                tags=["cors", "web-security", "exploitation"],
            )

        # SSL/TLS
        ssl = phase.get("ssl", {})
        if isinstance(ssl, dict):
            protocol = str(ssl.get("protocol", "")).lower()
            if any(weak in protocol for weak in ["tlsv1.0", "tlsv1.1", "sslv3", "sslv2"]):
                self.add_finding(
                    "Weak TLS/SSL Protocol Supported",
                    Severity.MEDIUM,
                    f"The server supports deprecated protocols ({protocol}), "
                    "leaving connections vulnerable to downgrade attacks.",
                    evidence=protocol,
                    recommendation="Disable TLS 1.0/1.1 and SSLv3. Enforce TLS 1.2+ only.",
                    tags=["ssl", "tls", "cryptography"],
                )
            if ssl.get("expired"):
                self.add_finding(
                    "Expired SSL Certificate",
                    Severity.HIGH,
                    "The SSL certificate has expired, causing browser warnings and "
                    "potential man-in-the-middle exposure.",
                    recommendation="Renew the certificate immediately via your CA or ACME provider.",
                    tags=["ssl", "certificate", "expired"],
                )

    # -- vulnerability assessment ---------------------------------------
    def _analyze_vulns(self, phase: dict[str, Any]) -> None:
        vuln_data = phase.get("vuln2", {})
        cve_data = phase.get("cve", {})

        vulns = []
        if isinstance(vuln_data, dict):
            vulns = vuln_data.get("vulnerabilities", vuln_data.get("findings", []))
        if isinstance(vuln_data, list):
            vulns = vuln_data

        for vuln in (vulns if isinstance(vulns, list) else []):
            vuln_str = str(vuln).lower()
            title = vuln.get("title", vuln.get("name", "Unknown Vulnerability")) if isinstance(vuln, dict) else str(vuln)[:80]
            cvss = vuln.get("cvss", 0) if isinstance(vuln, dict) else 0

            if any(kw in vuln_str for kw in ["rce", "remote code", "command injection", "deserialization"]):
                severity = Severity.CRITICAL
            elif any(kw in vuln_str for kw in ["sqli", "sql injection", "xss", "auth bypass"]):
                severity = Severity.HIGH
            elif cvss and float(cvss) >= 9.0:
                severity = Severity.CRITICAL
            elif cvss and float(cvss) >= 7.0:
                severity = Severity.HIGH
            elif cvss and float(cvss) >= 4.0:
                severity = Severity.MEDIUM
            else:
                severity = Severity.LOW

            self.add_finding(
                f"Vulnerability: {title[:80]}",
                severity,
                f"Identified vulnerability with exploit potential. CVSS: {cvss or 'N/A'}.",
                evidence=str(vuln)[:500],
                recommendation="Patch or mitigate immediately based on vendor advisory.",
                tags=["vulnerability", "exploit-candidate"],
            )

        # CVE cross-reference
        cves = []
        if isinstance(cve_data, dict):
            cves = cve_data.get("cves", cve_data.get("results", []))
        if isinstance(cve_data, list):
            cves = cve_data

        for cve in (cves if isinstance(cves, list) else [])[:10]:
            cve_id = cve.get("id", cve.get("cve_id", "")) if isinstance(cve, dict) else str(cve)
            if cve_id:
                self.add_finding(
                    f"CVE Mapped: {cve_id}",
                    Severity.HIGH,
                    f"Known CVE {cve_id} applies to a detected service or component.",
                    evidence=str(cve)[:400],
                    recommendation=f"Review {cve_id} in NVD and apply the vendor patch.",
                    tags=["cve", "exploit-mapping"],
                )

    # -- fuzzing --------------------------------------------------------
    def _analyze_fuzzing(self, phase: dict[str, Any]) -> None:
        fuzz = phase.get("fuzz", {})
        if not isinstance(fuzz, dict):
            return

        crashes = fuzz.get("crashes", fuzz.get("errors", []))
        if isinstance(crashes, list) and crashes:
            self.add_finding(
                f"Fuzzing Anomalies Detected ({len(crashes)})",
                Severity.HIGH,
                f"Input fuzzing triggered {len(crashes)} unexpected responses or crashes, "
                "indicating potential injection points or unhandled edge cases.",
                evidence=str(crashes[:3])[:500],
                recommendation="Investigate each anomaly. Validate and sanitize all user inputs.",
                tags=["fuzzing", "input-validation", "injection"],
            )

    # -- cross-phase correlation ----------------------------------------
    def _correlate_findings(self) -> None:
        titles = " ".join(f.title + " " + f.description for f in self.findings).lower()

        has_cve = any("cve" in f.title.lower() for f in self.findings)
        has_exposed_port = any("high-risk" in f.title.lower() for f in self.findings)
        has_web_vuln = any(
            kw in titles for kw in ["cors", "xss", "sqli", "injection", "rce"]
        )

        if has_cve and has_exposed_port:
            self.add_finding(
                "Attack Chain: Exposed Service + Known CVE",
                Severity.CRITICAL,
                "A publicly reachable service has a known CVE — this combination "
                "creates a directly exploitable attack path with no additional access required.",
                recommendation="Isolate the service behind a firewall and apply the CVE patch immediately.",
                tags=["attack-chain", "critical-path", "correlation"],
            )

        if has_web_vuln and has_exposed_port:
            self.add_finding(
                "Compound Risk: Web Vulnerability on Exposed Service",
                Severity.HIGH,
                "A web-layer vulnerability was found on a service exposed to the internet, "
                "increasing the likelihood of successful exploitation.",
                recommendation="Prioritize remediation of the web vulnerability and restrict service exposure.",
                tags=["compound-risk", "correlation"],
            )

    # ── handoff ────────────────────────────────────────────────────────
    def handoff(self) -> list[str]:
        agents: list[str] = []
        titles_lower = " ".join(f.title.lower() for f in self.findings)
        descs_lower = " ".join(f.description.lower() for f in self.findings)
        all_text = titles_lower + " " + descs_lower

        has_vulns = any(f.severity in (Severity.CRITICAL, Severity.HIGH) for f in self.findings)
        has_cloud = "cloud" in all_text
        has_web = any(kw in all_text for kw in ["cors", "header", "xss", "web"])
        has_creds = any(kw in all_text for kw in ["secret", "credential", "token", "api key"])

        if has_vulns:
            agents.append("exploit-agent")
        if has_cloud:
            agents.append("cloud-agent")
        if has_web:
            agents.append("web-agent")
        if has_creds:
            agents.append("password-agent")
        if not agents and self.findings:
            agents.append("report-agent")

        return agents

    # ── helpers ────────────────────────────────────────────────────────
    @staticmethod
    def _is_high_risk_port(port: Any) -> bool:
        high_risk = {21, 22, 23, 445, 1433, 1521, 3306, 3389, 5432, 5900, 6379, 9200, 27017}
        try:
            return int(port) in high_risk
        except (ValueError, TypeError):
            return False

    @staticmethod
    def _check_missing_headers(headers: dict) -> list[str]:
        required = [
            "Content-Security-Policy",
            "X-Frame-Options",
            "X-Content-Type-Options",
            "Strict-Transport-Security",
            "Referrer-Policy",
            "Permissions-Policy",
        ]
        present = {k.lower() for k in headers}
        return [h for h in required if h.lower() not in present]
