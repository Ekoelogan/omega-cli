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
        if any(kw in task_lower for kw in ["report", "pdf", "summary"]):
            return ["report-agent"]
        if any(kw in task_lower for kw in ["full", "auto", "everything", "complete"]):
            return ["recon-agent", "web-agent", "cloud-agent", "vuln-agent", "report-agent"]

        # Default: recon
        return ["recon-agent"]

    @classmethod
    def auto_register(cls):
        """Import and register all built-in specialist agents."""
        try:
            from omega_cli.agents.specialists.recon_agent import ReconAgent
            cls.register("recon-agent", ReconAgent)
        except ImportError:
            pass
        try:
            from omega_cli.agents.specialists.web_agent import WebAgent
            cls.register("web-agent", WebAgent)
        except ImportError:
            pass
        try:
            from omega_cli.agents.specialists.vuln_agent import VulnAgent
            cls.register("vuln-agent", VulnAgent)
        except ImportError:
            pass
        try:
            from omega_cli.agents.specialists.cloud_agent import CloudAgent
            cls.register("cloud-agent", CloudAgent)
        except ImportError:
            pass
        try:
            from omega_cli.agents.specialists.social_agent import SocialAgent
            cls.register("social-agent", SocialAgent)
        except ImportError:
            pass
        try:
            from omega_cli.agents.specialists.report_agent import ReportAgent
            cls.register("report-agent", ReportAgent)
        except ImportError:
            pass
