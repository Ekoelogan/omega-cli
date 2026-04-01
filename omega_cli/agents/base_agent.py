"""BaseAgent — abstract foundation for all OMEGA specialist agents."""
from __future__ import annotations

import json
import time
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional

from rich.console import Console
from rich.panel import Panel

console = Console()


class AgentStatus(str, Enum):
    IDLE = "idle"
    PLANNING = "planning"
    EXECUTING = "executing"
    ANALYZING = "analyzing"
    REPORTING = "reporting"
    COMPLETE = "complete"
    ERROR = "error"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class Finding:
    """A single security finding produced by an agent."""
    title: str
    severity: Severity
    description: str
    evidence: str = ""
    recommendation: str = ""
    tags: list[str] = field(default_factory=list)
    source_agent: str = ""
    target: str = ""
    raw_data: dict = field(default_factory=dict)


@dataclass
class AgentResult:
    """Result returned after an agent completes its work."""
    agent_name: str
    target: str
    status: AgentStatus
    findings: list[Finding] = field(default_factory=list)
    summary: str = ""
    raw_output: dict = field(default_factory=dict)
    duration_seconds: float = 0.0
    error: str = ""
    next_agents: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "agent": self.agent_name,
            "target": self.target,
            "status": self.status.value,
            "summary": self.summary,
            "findings": [
                {
                    "title": f.title,
                    "severity": f.severity.value,
                    "description": f.description,
                    "evidence": f.evidence,
                    "recommendation": f.recommendation,
                    "tags": f.tags,
                }
                for f in self.findings
            ],
            "duration": self.duration_seconds,
            "error": self.error,
            "next_agents": self.next_agents,
        }


class BaseAgent(ABC):
    """Abstract base class for all OMEGA specialist agents.

    Lifecycle: plan() → execute() → analyze() → report()
    Agents can also handoff() to suggest next agents.
    """

    name: str = "base"
    description: str = "Base agent"
    category: str = "general"
    capabilities: list[str] = []
    tools: list[str] = []  # omega commands this agent uses

    def __init__(self, target: str, memory: Optional[Any] = None,
                 executor: Optional[Any] = None, config: Optional[dict] = None):
        self.target = target
        self.memory = memory
        self.executor = executor
        self.config = config or {}
        self.agent_id = str(uuid.uuid4())[:8]
        self.status = AgentStatus.IDLE
        self.findings: list[Finding] = []
        self._start_time = 0.0
        self._log: list[str] = []

    def log(self, msg: str):
        """Append to agent execution log."""
        self._log.append(f"[{self.name}] {msg}")
        console.print(f"  [dim #ff85b3]⟫[/] [dim]{msg}[/]")

    def add_finding(self, title: str, severity: Severity, description: str,
                    evidence: str = "", recommendation: str = "",
                    tags: list[str] | None = None, raw_data: dict | None = None):
        """Register a security finding."""
        f = Finding(
            title=title,
            severity=severity,
            description=description,
            evidence=evidence,
            recommendation=recommendation,
            tags=tags or [],
            source_agent=self.name,
            target=self.target,
            raw_data=raw_data or {},
        )
        self.findings.append(f)
        if self.memory:
            self.memory.store_finding(self.target, self.name, f)

    @abstractmethod
    def plan(self) -> list[str]:
        """Determine which tools/steps to run. Returns list of step descriptions."""
        ...

    @abstractmethod
    def execute(self) -> dict[str, Any]:
        """Run the planned tools, collect raw data. Returns aggregated results."""
        ...

    @abstractmethod
    def analyze(self, data: dict[str, Any]) -> list[Finding]:
        """Analyze raw data, produce findings."""
        ...

    def report(self) -> AgentResult:
        """Compile final result from findings."""
        duration = time.time() - self._start_time if self._start_time else 0
        summary_parts = []
        by_sev = {}
        for f in self.findings:
            by_sev.setdefault(f.severity.value, []).append(f)
        for sev in ["critical", "high", "medium", "low", "info"]:
            count = len(by_sev.get(sev, []))
            if count:
                summary_parts.append(f"{count} {sev}")
        summary = f"{self.name} found {', '.join(summary_parts) or 'no issues'} on {self.target}"

        return AgentResult(
            agent_name=self.name,
            target=self.target,
            status=self.status,
            findings=self.findings,
            summary=summary,
            duration_seconds=round(duration, 2),
            next_agents=self.handoff(),
        )

    def handoff(self) -> list[str]:
        """Suggest which agents should run next based on findings."""
        return []

    def run(self) -> AgentResult:
        """Full lifecycle: plan → execute → analyze → report."""
        self._start_time = time.time()

        console.print(Panel(
            f"[bold #ff2d78]🤖 {self.name}[/] → [cyan]{self.target}[/]\n"
            f"[dim]{self.description}[/]",
            border_style="#ff85b3",
        ))

        try:
            # Plan
            self.status = AgentStatus.PLANNING
            steps = self.plan()
            self.log(f"Plan: {len(steps)} steps")
            for i, step in enumerate(steps, 1):
                self.log(f"  {i}. {step}")

            # Execute
            self.status = AgentStatus.EXECUTING
            raw_data = self.execute()
            self.log(f"Execution complete — {len(raw_data)} data sources")

            # Analyze
            self.status = AgentStatus.ANALYZING
            self.findings = self.analyze(raw_data)
            self.log(f"Analysis complete — {len(self.findings)} findings")

            # Store in memory
            if self.memory:
                self.memory.store_run(self.target, self.name, raw_data, self.findings)

            self.status = AgentStatus.COMPLETE

        except Exception as e:
            self.status = AgentStatus.ERROR
            self.log(f"Error: {e}")
            return AgentResult(
                agent_name=self.name,
                target=self.target,
                status=AgentStatus.ERROR,
                error=str(e),
                duration_seconds=round(time.time() - self._start_time, 2),
            )

        result = self.report()

        # Display summary
        sev_colors = {"critical": "red bold", "high": "red", "medium": "yellow", "low": "cyan", "info": "dim"}
        console.print(f"\n[bold #ff2d78]━━ {self.name} Results ━━[/]")
        for f in self.findings:
            style = sev_colors.get(f.severity.value, "dim")
            console.print(f"  [{style}]■ [{f.severity.value.upper()}][/{style}] {f.title}")
        if result.next_agents:
            console.print(f"  [dim]→ Recommended next: {', '.join(result.next_agents)}[/]")
        console.print(f"  [dim]⏱ {result.duration_seconds}s[/]\n")

        return result
