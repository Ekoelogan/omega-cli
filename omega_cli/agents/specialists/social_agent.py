"""SocialAgent — social media and identity OSINT specialist."""
from __future__ import annotations

from typing import Any

from omega_cli.agents.base_agent import BaseAgent, Finding, Severity


class SocialAgent(BaseAgent):
    name = "social-agent"
    description = "Social media and identity OSINT — usernames, emails, personas, social profiles"
    category = "social"
    capabilities = ["username_search", "email_osint", "social_profiles", "identity_correlation"]
    tools = ["username", "email", "social"]

    def plan(self) -> list[str]:
        return [
            "Email OSINT and breach check",
            "Username search across platforms",
            "Social media profile discovery",
            "Identity correlation",
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
        # Username results
        user_data = data.get("username", {})
        if isinstance(user_data, dict):
            platforms = user_data.get("found", user_data.get("profiles", []))
            if isinstance(platforms, list) and len(platforms) > 5:
                self.add_finding(
                    f"Username Active on {len(platforms)} Platforms",
                    Severity.INFO,
                    f"The target username/identity was found on {len(platforms)} platforms.",
                    evidence=", ".join(str(p) for p in platforms[:10]),
                    tags=["username", "social", "identity"],
                )

        # Email data
        email_data = data.get("email", {})
        if isinstance(email_data, dict):
            breaches = email_data.get("breaches", [])
            if breaches:
                self.add_finding(
                    f"Email Found in {len(breaches)} Breaches",
                    Severity.HIGH,
                    f"Target email appears in {len(breaches)} known data breaches.",
                    evidence=", ".join(str(b) for b in breaches[:5]),
                    recommendation="Change passwords, enable MFA, monitor for credential stuffing.",
                    tags=["email", "breach", "credential-exposure"],
                )

        return self.findings

    def handoff(self) -> list[str]:
        has_breach = any("Breach" in f.title for f in self.findings)
        return ["password-agent"] if has_breach else []
