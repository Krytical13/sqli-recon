"""Output formatters - generates sqlmap-ready files, JSON reports, and terminal summaries."""

import json
import os
import re
import logging
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from sqli_recon.models import Finding, ParamLocation

log = logging.getLogger(__name__)


# ---- Terminal colors (ANSI) ----

class C:
    RED = "\033[91m"
    YELLOW = "\033[93m"
    GREEN = "\033[92m"
    CYAN = "\033[96m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RESET = "\033[0m"
    WHITE = "\033[97m"


def colorize_score(score):
    if score >= 0.7:
        return f"{C.RED}{C.BOLD}{score:.2f}{C.RESET}"
    elif score >= 0.4:
        return f"{C.YELLOW}{score:.2f}{C.RESET}"
    else:
        return f"{C.DIM}{score:.2f}{C.RESET}"


def colorize_risk(risk):
    if risk == "HIGH":
        return f"{C.RED}{C.BOLD}{risk}{C.RESET}"
    elif risk == "MEDIUM":
        return f"{C.YELLOW}{risk}{C.RESET}"
    return f"{C.DIM}{risk}{C.RESET}"


# ---- Output generators ----

class OutputGenerator:
    """Generates all output formats from a list of Findings."""

    def __init__(self, findings, output_dir=None):
        self.findings = findings
        self.output_dir = output_dir

    def generate_all(self):
        """Generate all output files and print summary."""
        if self.output_dir:
            os.makedirs(self.output_dir, exist_ok=True)
            requests_dir = os.path.join(self.output_dir, "requests")
            os.makedirs(requests_dir, exist_ok=True)

            urls_path = os.path.join(self.output_dir, "sqlmap_urls.txt")
            report_path = os.path.join(self.output_dir, "report.json")
            commands_path = os.path.join(self.output_dir, "sqlmap_commands.sh")

            urls_written = self.write_sqlmap_urls(urls_path)
            requests_written = self.write_sqlmap_requests(requests_dir)
            self.write_json_report(report_path)
            self.write_sqlmap_commands(commands_path, requests_dir)

            return {
                "urls_file": urls_path,
                "urls_count": urls_written,
                "requests_dir": requests_dir,
                "requests_count": requests_written,
                "report_file": report_path,
                "commands_file": commands_path,
            }
        return {}

    # ---- sqlmap URL list (for -m flag) ----

    def write_sqlmap_urls(self, path):
        """Write sqlmap-compatible URLs with * injection markers."""
        urls = []
        seen = set()

        for finding in self.findings:
            url = self._build_marked_url(finding)
            if url and url not in seen:
                seen.add(url)
                urls.append(url)

        with open(path, "w") as f:
            f.write("\n".join(urls) + "\n" if urls else "")

        return len(urls)

    def _build_marked_url(self, finding):
        """Build a URL with sqlmap injection marker * on the target parameter."""
        ep = finding.endpoint
        param = finding.parameter
        parsed = urlparse(ep.url)

        if param.location == ParamLocation.QUERY:
            qs = parse_qs(parsed.query, keep_blank_values=True)
            parts = []
            found = False
            for key in qs:
                val = qs[key][0] if qs[key] else ""
                if key == param.name:
                    parts.append(f"{key}={val}*" if val else f"{key}=*")
                    found = True
                else:
                    parts.append(f"{key}={val}")
            if not found:
                parts.append(f"{param.name}=*")
            new_query = "&".join(parts)
            return urlunparse((parsed.scheme, parsed.netloc, parsed.path,
                               parsed.params, new_query, ""))

        elif param.location == ParamLocation.PATH:
            # Mark the path parameter value with *
            path = parsed.path
            # Replace the detected value in the path
            if param.value:
                path = path.replace(param.value, param.value + "*", 1)
            else:
                # For route template params like {id}
                path = re.sub(r"\{" + re.escape(param.name) + r"\}", "*", path)
            return urlunparse((parsed.scheme, parsed.netloc, path,
                               parsed.params, parsed.query, ""))

        # For body/json params, return the base URL (user needs -r file or --data)
        return ep.base_url

    # ---- sqlmap request files (for -r flag) ----

    def write_sqlmap_requests(self, directory):
        """Write individual request files for sqlmap -r."""
        count = 0

        for i, finding in enumerate(self.findings):
            request_text = finding.sqlmap_request()
            if not request_text:
                continue

            # Generate descriptive filename
            ep = finding.endpoint
            param = finding.parameter
            parsed = urlparse(ep.url)
            path_slug = parsed.path.strip("/").replace("/", "_")[:40] or "root"
            filename = f"{i+1:03d}_{ep.method}_{path_slug}_{param.name}.txt"
            filename = re.sub(r"[^a-zA-Z0-9_.\-]", "_", filename)

            filepath = os.path.join(directory, filename)
            with open(filepath, "w") as f:
                f.write(request_text)
            count += 1

        return count

    # ---- JSON report ----

    def write_json_report(self, path):
        """Write full JSON report with all findings."""
        report = {
            "summary": {
                "total_findings": len(self.findings),
                "high_risk": sum(1 for f in self.findings if f.risk_level == "HIGH"),
                "medium_risk": sum(1 for f in self.findings if f.risk_level == "MEDIUM"),
                "low_risk": sum(1 for f in self.findings if f.risk_level == "LOW"),
            },
            "findings": [
                {
                    "score": round(f.score, 3),
                    "risk": f.risk_level,
                    "method": f.endpoint.method,
                    "url": f.endpoint.url,
                    "base_url": f.endpoint.base_url,
                    "parameter": f.parameter.name,
                    "param_location": f.parameter.location.value,
                    "param_type": f.parameter.param_type,
                    "param_value": f.parameter.value,
                    "source": f.endpoint.source.value,
                    "content_type": f.endpoint.content_type,
                    "reasons": f.reasons,
                    "sqlmap_url": self._build_marked_url(f),
                }
                for f in self.findings
            ],
        }

        with open(path, "w") as f:
            json.dump(report, f, indent=2)

    # ---- sqlmap command suggestions ----

    def write_sqlmap_commands(self, path, requests_dir):
        """Write a shell script with suggested sqlmap commands for each finding."""
        lines = [
            "#!/bin/bash",
            "# Auto-generated sqlmap commands from sqli_recon",
            "# Review and adjust before running!",
            "",
        ]

        # Batch mode command
        urls_file = os.path.join(os.path.dirname(path), "sqlmap_urls.txt")
        lines.append(f"# === Batch scan all URL findings ===")
        lines.append(f"# sqlmap -m {urls_file} --batch --smart --level=2 --risk=1")
        lines.append("")

        # Individual commands for high-risk findings
        lines.append("# === Individual high-value targets ===")
        for i, finding in enumerate(self.findings):
            if finding.risk_level not in ("HIGH", "MEDIUM"):
                continue

            ep = finding.endpoint
            param = finding.parameter
            lines.append(f"# [{finding.risk_level}] {ep.method} {ep.base_url} -> {param.name}")

            if param.location in (ParamLocation.QUERY, ParamLocation.PATH):
                url = self._build_marked_url(finding)
                lines.append(f"# sqlmap -u \"{url}\" --batch --level=2 --risk=1")
            elif param.location == ParamLocation.JSON:
                # JSON bodies work best with -r + explicit -p flag
                req_files = [f for f in os.listdir(requests_dir)
                             if f.startswith(f"{i+1:03d}_")] if os.path.isdir(requests_dir) else []
                if req_files:
                    req_path = os.path.join(requests_dir, req_files[0])
                    lines.append(f"# sqlmap -r \"{req_path}\" -p {param.name} --batch --level=2 --risk=1")
                else:
                    body = finding._build_request_body() if hasattr(finding, '_build_request_body') else f'{{\"{param.name}\": \"test\"}}'
                    lines.append(f"# sqlmap -u \"{ep.base_url}\" --method=POST "
                                 f"--data='{body}' "
                                 f"--headers=\"Content-Type: application/json\" "
                                 f"-p {param.name} --batch --level=2 --risk=1")
            elif param.location == ParamLocation.BODY:
                req_files = [f for f in os.listdir(requests_dir)
                             if f.startswith(f"{i+1:03d}_")] if os.path.isdir(requests_dir) else []
                if req_files:
                    req_path = os.path.join(requests_dir, req_files[0])
                    lines.append(f"# sqlmap -r \"{req_path}\" --batch --level=2 --risk=1")
                else:
                    lines.append(f"# sqlmap -u \"{ep.base_url}\" --data=\"{param.name}=test\" --batch")
            lines.append("")

        with open(path, "w") as f:
            f.write("\n".join(lines))
        os.chmod(path, 0o755)

    # ---- Terminal summary ----

    def print_summary(self, max_rows=50):
        """Print a formatted summary table to the terminal."""
        if not self.findings:
            print(f"\n{C.YELLOW}No potential SQLi surfaces found.{C.RESET}")
            return

        high = sum(1 for f in self.findings if f.risk_level == "HIGH")
        med = sum(1 for f in self.findings if f.risk_level == "MEDIUM")
        low = sum(1 for f in self.findings if f.risk_level == "LOW")

        print(f"\n{C.BOLD}{'=' * 90}{C.RESET}")
        print(f"{C.BOLD}  SQLi Surface Discovery Report{C.RESET}")
        print(f"{C.BOLD}{'=' * 90}{C.RESET}")
        print(f"  {C.RED}{C.BOLD}{high} HIGH{C.RESET}  "
              f"{C.YELLOW}{med} MEDIUM{C.RESET}  "
              f"{C.DIM}{low} LOW{C.RESET}  "
              f"({len(self.findings)} total)")
        print(f"{C.BOLD}{'-' * 90}{C.RESET}")

        # Table header
        print(f"  {'Score':<7} {'Risk':<8} {'Method':<7} {'Endpoint':<32} {'Param':<16} {'Loc':<7} {'Source':<6}")
        print(f"  {'─' * 7} {'─' * 8} {'─' * 7} {'─' * 32} {'─' * 16} {'─' * 7} {'─' * 6}")

        for finding in self.findings[:max_rows]:
            ep = finding.endpoint
            param = finding.parameter
            parsed = urlparse(ep.url)
            path_display = parsed.path[:30] + ".." if len(parsed.path) > 32 else parsed.path

            score_str = colorize_score(finding.score)
            risk_str = colorize_risk(finding.risk_level)

            print(f"  {score_str:<18} {risk_str:<19} {ep.method:<7} "
                  f"{path_display:<32} {param.name:<16} "
                  f"{param.location.value:<7} {ep.source.value:<6}")

        if len(self.findings) > max_rows:
            remaining = len(self.findings) - max_rows
            print(f"  {C.DIM}... and {remaining} more{C.RESET}")

        print(f"{C.BOLD}{'=' * 90}{C.RESET}")

    def print_top_reasons(self, top_n=10):
        """Print scoring reasons for the top findings."""
        print(f"\n{C.BOLD}Top {min(top_n, len(self.findings))} findings - scoring breakdown:{C.RESET}")
        print(f"{C.BOLD}{'-' * 60}{C.RESET}")

        for finding in self.findings[:top_n]:
            ep = finding.endpoint
            param = finding.parameter
            score_str = colorize_score(finding.score)
            print(f"\n  {score_str} {C.BOLD}{ep.method} {ep.base_url}{C.RESET}")
            print(f"       param: {C.CYAN}{param.name}{C.RESET} ({param.location.value}, {param.param_type})")
            for reason in finding.reasons:
                print(f"       {C.DIM}+ {reason}{C.RESET}")
