"""ToolExecutor — runs omega commands and external tools, captures structured output."""
from __future__ import annotations

import io
import json
import subprocess
import time
from typing import Any, Optional

from rich.console import Console

console = Console()


class ToolResult:
    """Structured result from a tool execution."""

    def __init__(self, tool: str, success: bool, data: Any = None,
                 output: str = "", error: str = "", duration: float = 0.0):
        self.tool = tool
        self.success = success
        self.data = data or {}
        self.output = output
        self.error = error
        self.duration = duration

    def to_dict(self) -> dict:
        return {
            "tool": self.tool,
            "success": self.success,
            "data": self.data,
            "output": self.output[:2000] if self.output else "",
            "error": self.error,
            "duration": self.duration,
        }


class ToolExecutor:
    """Executes omega modules and external Kali tools with structured output capture.

    Two modes:
      1. Python-native: import and call omega module .run() / .lookup() directly
      2. External CLI: subprocess execution for nmap, nikto, etc.
    """

    # Map of omega command names to their module paths and callable functions
    OMEGA_MODULES = {
        "whois":       ("omega_cli.modules.whois_lookup", "run"),
        "dns":         ("omega_cli.modules.dns_lookup", "run"),
        "subdomain":   ("omega_cli.modules.subdomain", "run"),
        "ipinfo":      ("omega_cli.modules.ipinfo", "run"),
        "headers":     ("omega_cli.modules.headers", "run"),
        "ssl":         ("omega_cli.modules.ssl_check", "run"),
        "ports":       ("omega_cli.modules.portscan", "run"),
        "crtsh":       ("omega_cli.modules.crtsh", "run"),
        "tech":        ("omega_cli.modules.techfp", "run"),
        "dorks":       ("omega_cli.modules.dorks", "run"),
        "wayback":     ("omega_cli.modules.wayback", "run"),
        "spider":      ("omega_cli.modules.spider", "run"),
        "jscan":       ("omega_cli.modules.jscan", "run"),
        "cors":        ("omega_cli.modules.corscheck", "run"),
        "spoofcheck":  ("omega_cli.modules.spoofcheck", "run"),
        "cloud":       ("omega_cli.modules.cloudrecon", "run"),
        "buckets":     ("omega_cli.modules.buckets", "run"),
        "email":       ("omega_cli.modules.email_osint", "run"),
        "username":    ("omega_cli.modules.username", "run"),
        "social":      ("omega_cli.modules.social", "run"),
        "reverseip":   ("omega_cli.modules.reverseip", "run"),
        "asn":         ("omega_cli.modules.asnrecon", "run"),
        "crypto":      ("omega_cli.modules.crypto", "run"),
        "ioc":         ("omega_cli.modules.ioc", "run"),
        "cve":         ("omega_cli.modules.nvd_cve", "run"),
        "vuln":        ("omega_cli.modules.vuln2", "run"),
        "hunt":        ("omega_cli.modules.hunt", "run"),
        "recon":       ("omega_cli.modules.recon", "run"),
        "auto":        ("omega_cli.modules.autorecon", "run"),
        "breach":      ("omega_cli.modules.breachcheck", "run"),
        "leaked":      ("omega_cli.modules.leaked", "run"),
        "dark":        ("omega_cli.modules.dark", "run"),
        "malware":     ("omega_cli.modules.malware", "run"),
        "phish":       ("omega_cli.modules.phishcheck", "run"),
        "opsec":       ("omega_cli.modules.opsec", "run"),
        "crawl":       ("omega_cli.modules.crawl", "run"),
        "secrets":     ("omega_cli.modules.secrets", "run"),
        "fuzzer":      ("omega_cli.modules.fuzzer", "run"),
    }

    # External tools that can be invoked via subprocess
    EXTERNAL_TOOLS = {
        "nmap":    "nmap",
        "nikto":   "nikto",
        "sqlmap":  "sqlmap",
        "gobuster": "gobuster",
        "ffuf":    "ffuf",
        "wfuzz":   "wfuzz",
        "hydra":   "hydra",
        "john":    "john",
        "hashcat": "hashcat",
        "dirb":    "dirb",
        "whatweb":  "whatweb",
        "wafw00f":  "wafw00f",
        "subfinder": "subfinder",
        "httpx":    "httpx",
        "nuclei":   "nuclei",
        "amass":    "amass",
        "masscan":  "masscan",
        "theHarvester": "theHarvester",
    }

    def __init__(self, timeout: int = 120):
        self.timeout = timeout

    def run_omega(self, tool_name: str, target: str, **kwargs) -> ToolResult:
        """Run an omega module natively (Python import)."""
        start = time.time()

        if tool_name not in self.OMEGA_MODULES:
            return ToolResult(
                tool=tool_name, success=False,
                error=f"Unknown omega tool: {tool_name}",
            )

        module_path, func_name = self.OMEGA_MODULES[tool_name]

        try:
            import importlib
            mod = importlib.import_module(module_path)
            func = getattr(mod, func_name)

            # Capture Rich console output
            buf = io.StringIO()
            capture_console = Console(file=buf, highlight=False, markup=False, width=200)

            # Call the module function
            result = func(target, **kwargs)
            output = buf.getvalue()
            duration = round(time.time() - start, 2)

            return ToolResult(
                tool=tool_name, success=True,
                data=result if isinstance(result, (dict, list)) else {},
                output=output, duration=duration,
            )

        except Exception as e:
            duration = round(time.time() - start, 2)
            return ToolResult(
                tool=tool_name, success=False,
                error=str(e), duration=duration,
            )

    def run_external(self, tool_name: str, args: list[str],
                     timeout: Optional[int] = None) -> ToolResult:
        """Run an external CLI tool via subprocess."""
        start = time.time()
        actual_timeout = timeout or self.timeout

        binary = self.EXTERNAL_TOOLS.get(tool_name, tool_name)

        try:
            proc = subprocess.run(
                [binary] + args,
                capture_output=True,
                text=True,
                timeout=actual_timeout,
            )
            duration = round(time.time() - start, 2)

            return ToolResult(
                tool=tool_name,
                success=proc.returncode == 0,
                data={"returncode": proc.returncode},
                output=proc.stdout,
                error=proc.stderr if proc.returncode != 0 else "",
                duration=duration,
            )

        except subprocess.TimeoutExpired:
            return ToolResult(
                tool=tool_name, success=False,
                error=f"Timeout after {actual_timeout}s",
                duration=actual_timeout,
            )
        except FileNotFoundError:
            return ToolResult(
                tool=tool_name, success=False,
                error=f"{binary} not found — install it first",
                duration=round(time.time() - start, 2),
            )
        except Exception as e:
            return ToolResult(
                tool=tool_name, success=False,
                error=str(e),
                duration=round(time.time() - start, 2),
            )

    def run_nmap(self, target: str, scan_type: str = "-sV",
                 ports: str = "", extra: str = "") -> ToolResult:
        """Convenience wrapper for nmap scans."""
        args = [scan_type]
        if ports:
            args.extend(["-p", ports])
        if extra:
            args.extend(extra.split())
        args.append(target)
        return self.run_external("nmap", args, timeout=300)

    def is_available(self, tool_name: str) -> bool:
        """Check if an external tool is installed."""
        import shutil
        binary = self.EXTERNAL_TOOLS.get(tool_name, tool_name)
        return shutil.which(binary) is not None

    def list_available(self) -> dict[str, bool]:
        """List all known external tools and their availability."""
        return {name: self.is_available(name) for name in self.EXTERNAL_TOOLS}

    def run(self, tool_name: str, target: str = "", args: list[str] | None = None,
            **kwargs) -> ToolResult:
        """Unified run: tries omega module first, falls back to external."""
        if tool_name in self.OMEGA_MODULES and target:
            return self.run_omega(tool_name, target, **kwargs)
        elif tool_name in self.EXTERNAL_TOOLS or args:
            return self.run_external(tool_name, args or [target])
        else:
            return ToolResult(
                tool=tool_name, success=False,
                error=f"Tool not found: {tool_name}",
            )
