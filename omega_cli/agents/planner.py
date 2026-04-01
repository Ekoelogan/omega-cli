"""AgentPlanner — AI-powered task decomposition for multi-step security operations."""
from __future__ import annotations

import json
from typing import Any, Optional

import httpx
from rich.console import Console

console = Console()


class AgentPlanner:
    """Decomposes high-level security tasks into ordered agent steps.

    Uses AI (Ollama/OpenAI) when available, falls back to rule-based planning.
    """

    # Rule-based task templates when no AI is available
    PLAYBOOKS = {
        "recon": [
            ("recon-agent", "Full passive reconnaissance"),
            ("web-agent", "Web application analysis"),
            ("cloud-agent", "Cloud asset discovery"),
            ("vuln-agent", "Vulnerability assessment"),
            ("report-agent", "Generate findings report"),
        ],
        "bug-bounty": [
            ("recon-agent", "Subdomain + DNS + OSINT enumeration"),
            ("web-agent", "Web app fingerprinting + header analysis"),
            ("vuln-agent", "Vulnerability scanning + CVE mapping"),
            ("exploit-agent", "Exploit verification (safe)"),
            ("report-agent", "Bug bounty report generation"),
        ],
        "threat-hunt": [
            ("recon-agent", "Target reconnaissance"),
            ("vuln-agent", "Vulnerability assessment"),
            ("forensics-agent", "IOC extraction + analysis"),
            ("report-agent", "Threat intelligence report"),
        ],
        "osint": [
            ("recon-agent", "Domain + IP + infrastructure OSINT"),
            ("social-agent", "Social media + identity OSINT"),
            ("privacy-agent", "Breach + data exposure check"),
            ("report-agent", "OSINT dossier generation"),
        ],
        "pentest": [
            ("recon-agent", "Target enumeration"),
            ("web-agent", "Web application testing"),
            ("vuln-agent", "Vulnerability assessment"),
            ("exploit-agent", "Exploitation attempts"),
            ("post-agent", "Post-exploitation analysis"),
            ("report-agent", "Pentest report"),
        ],
    }

    def __init__(self, config: Optional[dict] = None):
        self.config = config or {}

    def plan(self, task: str, target: str, context: dict | None = None) -> list[dict]:
        """Generate an execution plan for a given task.

        Returns list of: {"agent": str, "description": str, "priority": int}
        """
        # Try AI-powered planning first
        ai_plan = self._ai_plan(task, target, context)
        if ai_plan:
            return ai_plan

        # Rule-based fallback
        return self._rule_plan(task, target)

    def _rule_plan(self, task: str, target: str) -> list[dict]:
        """Rule-based planning from playbook templates."""
        task_lower = task.lower()

        # Match task to playbook
        matched = None
        for key, playbook in self.PLAYBOOKS.items():
            if key in task_lower:
                matched = playbook
                break

        if not matched:
            # Default to full recon
            matched = self.PLAYBOOKS["recon"]

        return [
            {"agent": agent, "description": desc, "priority": i + 1}
            for i, (agent, desc) in enumerate(matched)
        ]

    def _ai_plan(self, task: str, target: str, context: dict | None = None) -> list[dict]:
        """AI-powered planning using Ollama or OpenAI."""
        prompt = f"""You are an expert cybersecurity operations planner. Given a task and target, 
produce an ordered execution plan using these available agents:

AGENTS:
- recon-agent: Passive recon (WHOIS, DNS, subdomains, IPs, certificates, tech fingerprinting)
- web-agent: Web app analysis (headers, CORS, JS secrets, crawling, screenshots)
- vuln-agent: Vulnerability assessment (CVE mapping, misconfiguration detection)
- exploit-agent: Safe exploit verification (PoC validation only)
- cloud-agent: Cloud asset discovery (S3 buckets, Azure blobs, GCP storage)
- social-agent: Social media and identity OSINT
- forensics-agent: IOC extraction, malware analysis, STIX/TAXII
- password-agent: Credential analysis (leaked data, hash cracking)
- privacy-agent: Breach checks, data exposure assessment
- crypto-agent: Cryptocurrency OSINT
- report-agent: Report generation (PDF, HTML, JSON)

TASK: {task}
TARGET: {target}
CONTEXT: {json.dumps(context or {}, default=str)[:2000]}

Respond with a JSON array only. Each item: {{"agent": "name", "description": "what to do", "priority": N}}
JSON:"""

        # Try Ollama
        try:
            r = httpx.post(
                "http://localhost:11434/api/generate",
                json={"model": "llama3.2", "prompt": prompt, "stream": False, "format": "json"},
                timeout=30,
            )
            if r.status_code == 200:
                text = r.json().get("response", "")
                return self._parse_plan(text)
        except Exception:
            pass

        # Try OpenAI
        api_key = self.config.get("openai_api_key", "")
        if api_key:
            try:
                r = httpx.post(
                    "https://api.openai.com/v1/chat/completions",
                    headers={"Authorization": f"Bearer {api_key}"},
                    json={
                        "model": "gpt-4o-mini",
                        "messages": [{"role": "user", "content": prompt}],
                        "max_tokens": 500,
                        "temperature": 0.1,
                    },
                    timeout=15,
                )
                if r.status_code == 200:
                    text = r.json()["choices"][0]["message"]["content"]
                    return self._parse_plan(text)
            except Exception:
                pass

        return []  # Fall back to rule-based

    def _parse_plan(self, text: str) -> list[dict]:
        """Parse AI response into structured plan."""
        try:
            # Find JSON array in response
            text = text.strip()
            if text.startswith("{"):
                data = json.loads(text)
                if isinstance(data, dict) and "plan" in data:
                    return data["plan"]
            if text.startswith("["):
                return json.loads(text)
            # Try to extract JSON from markdown
            import re
            match = re.search(r'\[.*\]', text, re.DOTALL)
            if match:
                return json.loads(match.group())
        except Exception:
            pass
        return []
