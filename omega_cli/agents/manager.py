"""AgentManager — orchestrates multi-agent workflows and manages lifecycle."""
from __future__ import annotations

import json
import time
from typing import Any, Optional

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn

from omega_cli.agents.base_agent import AgentResult, AgentStatus
from omega_cli.agents.memory import AgentMemory
from omega_cli.agents.executor import ToolExecutor
from omega_cli.agents.planner import AgentPlanner
from omega_cli.agents.router import AgentRouter

console = Console()


class AgentManager:
    """Top-level orchestrator that manages the full agent pipeline.

    Workflow:
    1. Accept task + target from user
    2. Use Planner to decompose into steps
    3. Use Router to map steps to agents
    4. Execute agents sequentially, passing findings forward
    5. Aggregate results and generate report
    """

    def __init__(self, config: Optional[dict] = None):
        self.config = config or {}
        self.memory = AgentMemory()
        self.executor = ToolExecutor()
        self.planner = AgentPlanner(config=self.config)
        self.results: list[AgentResult] = []
        self._ensure_agents_registered()

    def _ensure_agents_registered(self):
        """Make sure all specialist agents are registered."""
        AgentRouter.auto_register()

    def run_task(self, task: str, target: str) -> list[AgentResult]:
        """Execute a high-level task: plan → route → execute agents → aggregate."""
        start_time = time.time()

        console.print(Panel(
            f"[bold #ff2d78]🧠 OMEGA Agent Manager[/]\n"
            f"[dim]Task:[/] [white]{task}[/]\n"
            f"[dim]Target:[/] [cyan]{target}[/]",
            border_style="#ff85b3",
        ))

        # 1. Plan
        console.print("\n[bold #ff2d78]Phase 1: Planning[/]")
        plan = self.planner.plan(task, target)
        for step in plan:
            console.print(f"  [dim]#{step['priority']}[/] [{step['agent']}] {step['description']}")

        # 2. Execute each agent in order
        console.print(f"\n[bold #ff2d78]Phase 2: Executing {len(plan)} agents[/]")
        self.results = []

        for step in plan:
            agent_name = step["agent"]
            agent_cls = AgentRouter.get(agent_name)

            if not agent_cls:
                console.print(f"  [yellow]⚠ Agent not found: {agent_name} — skipping[/]")
                continue

            # Instantiate and run the agent
            agent = agent_cls(
                target=target,
                memory=self.memory,
                executor=self.executor,
                config=self.config,
            )

            result = agent.run()
            self.results.append(result)

            # If an agent suggests more agents, check if we should add them
            for next_agent in result.next_agents:
                already_planned = any(s["agent"] == next_agent for s in plan)
                if not already_planned and AgentRouter.get(next_agent):
                    plan.append({
                        "agent": next_agent,
                        "description": f"Recommended by {agent_name}",
                        "priority": len(plan) + 1,
                    })
                    console.print(f"  [dim]+ Added {next_agent} (recommended by {agent_name})[/]")

        # 3. Aggregate
        console.print(f"\n[bold #ff2d78]Phase 3: Summary[/]")
        total_duration = round(time.time() - start_time, 2)
        self._print_summary(total_duration)

        return self.results

    def run_agent(self, agent_name: str, target: str) -> AgentResult:
        """Run a single specific agent."""
        self._ensure_agents_registered()
        agent_cls = AgentRouter.get(agent_name)

        if not agent_cls:
            console.print(f"[red]Agent not found: {agent_name}[/]")
            available = [a["name"] for a in AgentRouter.list_agents()]
            console.print(f"[dim]Available: {', '.join(available)}[/]")
            return AgentResult(
                agent_name=agent_name, target=target,
                status=AgentStatus.ERROR, error="Agent not found",
            )

        agent = agent_cls(
            target=target,
            memory=self.memory,
            executor=self.executor,
            config=self.config,
        )
        return agent.run()

    def _print_summary(self, total_duration: float):
        """Print aggregated results table."""
        table = Table(title="Agent Results", border_style="#ff85b3")
        table.add_column("Agent", style="bold #ff2d78")
        table.add_column("Status", style="cyan")
        table.add_column("Findings", justify="right")
        table.add_column("Critical", justify="right", style="red bold")
        table.add_column("High", justify="right", style="red")
        table.add_column("Medium", justify="right", style="yellow")
        table.add_column("Time", justify="right", style="dim")

        total_findings = 0
        total_critical = 0
        total_high = 0

        for r in self.results:
            crit = sum(1 for f in r.findings if f.severity.value == "critical")
            high = sum(1 for f in r.findings if f.severity.value == "high")
            med = sum(1 for f in r.findings if f.severity.value == "medium")
            total_findings += len(r.findings)
            total_critical += crit
            total_high += high

            status_icon = "✓" if r.status == AgentStatus.COMPLETE else "✗"
            table.add_row(
                r.agent_name, status_icon,
                str(len(r.findings)),
                str(crit) if crit else "—",
                str(high) if high else "—",
                str(med) if med else "—",
                f"{r.duration_seconds}s",
            )

        console.print(table)
        console.print(
            f"\n[bold]Total:[/] {total_findings} findings "
            f"({total_critical} critical, {total_high} high) "
            f"in {total_duration}s across {len(self.results)} agents\n"
        )

    def list_agents(self) -> list[dict]:
        """List all available agents."""
        self._ensure_agents_registered()
        return AgentRouter.list_agents()

    def get_memory_stats(self) -> dict:
        return self.memory.stats()

    def search_findings(self, query: str) -> list[dict]:
        return self.memory.search(query)
