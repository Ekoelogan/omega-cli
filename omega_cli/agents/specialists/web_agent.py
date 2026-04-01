"""WebAgent — web application security analysis specialist."""
from __future__ import annotations

from typing import Any

from omega_cli.agents.base_agent import BaseAgent, Finding, Severity


class WebAgent(BaseAgent):
    name = "web-agent"
    description = "Web application analysis — headers, CORS, JS secrets, crawling, screenshots"
    category = "web"
    capabilities = ["header_analysis", "cors_check", "js_scanning", "crawling", "tech_fingerprint"]
    tools = ["headers", "cors", "jscan", "crawl", "tech", "spider", "secrets"]

    def plan(self) -> list[str]:
        return [
            "HTTP header security analysis",
            "CORS misconfiguration check",
            "JavaScript secret scanning",
            "Web crawling for endpoints",
            "Technology fingerprinting",
        ]

    def execute(self) -> dict[str, Any]:
        data = {}
        for tool_name in self.tools:
            self.log(f"Running {tool_name}...")
            try:
                result = self.executor.run_omega(tool_name, self.target)
                if result.success and result.data:
                    data[tool_name] = result.data
                elif result.success:
                    data[tool_name] = {"output": result.output[:3000]}
                else:
                    self.log(f"  {tool_name}: {result.error}")
            except Exception as e:
                self.log(f"  {tool_name} error: {e}")
        return data

    def analyze(self, data: dict[str, Any]) -> list[Finding]:
        # Header analysis
        headers = data.get("headers", {})
        if isinstance(headers, dict):
            missing = []
            security_headers = [
                "Content-Security-Policy", "X-Frame-Options",
                "X-Content-Type-Options", "Strict-Transport-Security",
                "Referrer-Policy", "Permissions-Policy",
            ]
            header_keys_lower = {k.lower(): k for k in headers}
            for h in security_headers:
                if h.lower() not in header_keys_lower:
                    missing.append(h)

            if missing:
                sev = Severity.HIGH if len(missing) >= 4 else Severity.MEDIUM
                self.add_finding(
                    f"Missing Security Headers ({len(missing)})",
                    sev,
                    f"The following security headers are missing: {', '.join(missing)}",
                    recommendation="Add all missing security headers to the web server configuration.",
                    tags=["headers", "web-security"],
                )

        # CORS analysis
        cors_data = data.get("cors", {})
        if isinstance(cors_data, dict):
            if cors_data.get("vulnerable") or cors_data.get("misconfigured"):
                self.add_finding(
                    "CORS Misconfiguration",
                    Severity.HIGH,
                    "Cross-Origin Resource Sharing is misconfigured, potentially allowing "
                    "unauthorized cross-origin requests.",
                    evidence=str(cors_data)[:500],
                    recommendation="Restrict Access-Control-Allow-Origin to trusted domains only.",
                    tags=["cors", "web-security"],
                )

        # JS secrets
        js_data = data.get("jscan", {})
        if isinstance(js_data, dict):
            secrets_found = js_data.get("secrets", js_data.get("findings", []))
            if secrets_found:
                self.add_finding(
                    f"Secrets Found in JavaScript ({len(secrets_found)})",
                    Severity.CRITICAL,
                    "API keys, tokens, or other secrets were found in client-side JavaScript.",
                    evidence=str(secrets_found)[:500],
                    recommendation="Remove all secrets from client-side code. Use environment variables "
                    "and server-side proxies.",
                    tags=["secrets", "javascript", "credential-exposure"],
                )

        return self.findings

    def handoff(self) -> list[str]:
        has_secrets = any("Secret" in f.title for f in self.findings)
        has_cors = any("CORS" in f.title for f in self.findings)
        agents = []
        if has_secrets or has_cors:
            agents.append("vuln-agent")
        return agents
