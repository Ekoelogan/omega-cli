"""AgentRouter — dispatches tasks to the right specialist agent."""
from __future__ import annotations

from typing import Any, Optional

from rich.console import Console

console = Console()


class AgentRouter:
    """Routes tasks to appropriate specialist agents based on target type and task."""

    # Registry of all available agent classes
    _registry: dict[str, type] = {}

    @classmethod
    def register(cls, name: str, agent_class: type):
        """Register a specialist agent class."""
        cls._registry[name] = agent_class

    @classmethod
    def get(cls, name: str) -> Optional[type]:
        """Get a registered agent class by name."""
        return cls._registry.get(name)

    @classmethod
    def list_agents(cls) -> list[dict]:
        """List all registered agents with metadata."""
        agents = []
        for name, agent_cls in sorted(cls._registry.items()):
            agents.append({
                "name": name,
                "description": getattr(agent_cls, "description", ""),
                "category": getattr(agent_cls, "category", "general"),
                "capabilities": getattr(agent_cls, "capabilities", []),
                "tools": getattr(agent_cls, "tools", []),
            })
        return agents

    @classmethod
    def route(cls, task: str, target: str) -> list[str]:
        """Determine which agents to run for a given task/target combo.

        Returns ordered list of agent names.
        """
        task_lower = task.lower()

        # Direct agent request
        for name in cls._registry:
            if name.replace("-agent", "") in task_lower:
                return [name]

        # Task-based routing
        if any(kw in task_lower for kw in ["recon", "osint", "enumerate", "discover"]):
            return ["recon-agent"]
        if any(kw in task_lower for kw in ["vuln", "cve", "vulnerability", "scan"]):
            return ["recon-agent", "vuln-agent"]
        if any(kw in task_lower for kw in ["web", "http", "app", "site"]):
            return ["web-agent"]
        if any(kw in task_lower for kw in ["cloud", "s3", "azure", "gcp", "bucket"]):
            return ["cloud-agent"]
        if any(kw in task_lower for kw in ["bug bounty", "bounty", "pentest"]):
            return ["recon-agent", "web-agent", "vuln-agent", "report-agent"]
        if any(kw in task_lower for kw in ["social", "identity", "person", "username"]):
            return ["social-agent"]
        if any(kw in task_lower for kw in ["forensic", "ioc", "malware", "incident"]):
            return ["forensics-agent"]
        if any(kw in task_lower for kw in ["breach", "leaked", "credential", "password"]):
            return ["password-agent"]
        if any(kw in task_lower for kw in ["exploit", "metasploit", "sqlmap", "payload"]):
            return ["exploit-agent"]
        if any(kw in task_lower for kw in ["wifi", "wireless", "wlan", "aircrack"]):
            return ["wifi-agent"]
        if any(kw in task_lower for kw in ["reverse", "firmware", "binary", "disassembl"]):
            return ["reverse-agent"]
        if any(kw in task_lower for kw in ["post-exploit", "lateral", "pivot", "exfil", "c2"]):
            return ["post-agent"]
        if any(kw in task_lower for kw in ["privacy", "opsec", "tor", "anonymi", "darkweb", "dark web"]):
            return ["privacy-agent"]
        if any(kw in task_lower for kw in ["crypto", "blockchain", "bitcoin", "ethereum", "stego"]):
            return ["crypto-agent"]
        if any(kw in task_lower for kw in ["ai", "machine learning", "ml model", "llm"]):
            return ["ai-security-agent"]
        if any(kw in task_lower for kw in ["report", "pdf", "summary"]):
            return ["report-agent"]
        if any(kw in task_lower for kw in ["full", "auto", "everything", "complete"]):
            return ["recon-agent", "web-agent", "cloud-agent", "vuln-agent",
                     "password-agent", "report-agent"]

        # Default: recon
        return ["recon-agent"]

    @classmethod
    def auto_register(cls):
        """Import and register all built-in specialist agents."""
        _agents = [
            ("recon-agent", "omega_cli.agents.specialists.recon_agent", "ReconAgent"),
            ("web-agent", "omega_cli.agents.specialists.web_agent", "WebAgent"),
            ("vuln-agent", "omega_cli.agents.specialists.vuln_agent", "VulnAgent"),
            ("cloud-agent", "omega_cli.agents.specialists.cloud_agent", "CloudAgent"),
            ("social-agent", "omega_cli.agents.specialists.social_agent", "SocialAgent"),
            ("report-agent", "omega_cli.agents.specialists.report_agent", "ReportAgent"),
            ("exploit-agent", "omega_cli.agents.specialists.exploit_agent", "ExploitAgent"),
            ("wifi-agent", "omega_cli.agents.specialists.wifi_agent", "WifiAgent"),
            ("password-agent", "omega_cli.agents.specialists.password_agent", "PasswordAgent"),
            ("forensics-agent", "omega_cli.agents.specialists.forensics_agent", "ForensicsAgent"),
            ("reverse-agent", "omega_cli.agents.specialists.reverse_agent", "ReverseAgent"),
            ("post-agent", "omega_cli.agents.specialists.post_agent", "PostAgent"),
            ("privacy-agent", "omega_cli.agents.specialists.privacy_agent", "PrivacyAgent"),
            ("crypto-agent", "omega_cli.agents.specialists.crypto_agent", "CryptoAgent"),
            ("ai-security-agent", "omega_cli.agents.specialists.ai_security_agent", "AISecurityAgent"),
        ]
        for name, module_path, class_name in _agents:
            try:
                import importlib
                mod = importlib.import_module(module_path)
                agent_cls = getattr(mod, class_name)
                cls.register(name, agent_cls)
            except (ImportError, AttributeError):
                pass
