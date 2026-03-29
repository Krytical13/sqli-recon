"""Output formatters - generates sqlmap-ready files, JSON reports, and terminal summaries."""

import json
import os
import re
import logging
import shlex
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from sqli_recon.models import Finding, ParamLocation


def _shell_quote(s):
    """Quote a string for safe shell use."""
    return shlex.quote(s)

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

    def __init__(self, findings, output_dir=None, sqlmap_extra_flags=None,
                 sqlmap_notes=None, session_cookie=None, user_agent=None, proxy=None):
        self.findings = findings
        self.output_dir = output_dir
        self.sqlmap_extra_flags = sqlmap_extra_flags or []
        self.sqlmap_notes = sqlmap_notes or []
        self.session_cookie = session_cookie  # Full cookie string from auth
        self.user_agent = user_agent
        self.proxy = proxy

    def generate_all(self):
        """Generate all output files and print summary."""
        if self.output_dir:
            os.makedirs(self.output_dir, exist_ok=True)
            requests_dir = os.path.join(self.output_dir, "requests")
            os.makedirs(requests_dir, exist_ok=True)

            urls_path = os.path.join(self.output_dir, "sqlmap_urls.txt")
            report_path = os.path.join(self.output_dir, "report.json")
            runner_path = os.path.join(self.output_dir, "run_sqlmap.sh")

            urls_written = self.write_sqlmap_urls(urls_path)
            requests_written = self.write_sqlmap_requests(requests_dir)
            self.write_json_report(report_path)
            self.write_sqlmap_runner(runner_path, requests_dir)

            return {
                "urls_file": urls_path,
                "urls_count": urls_written,
                "requests_dir": requests_dir,
                "requests_count": requests_written,
                "report_file": report_path,
                "runner_file": runner_path,
            }
        return {}

    # ---- sqlmap URL list (for -m flag) ----

    def write_sqlmap_urls(self, path):
        """Write sqlmap-compatible URLs with * injection markers.

        Only includes GET query param and path param findings — POST body/JSON
        params can't be expressed as URLs and must use -r request files instead.
        """
        urls = []
        seen = set()

        for finding in self.findings:
            if finding.parameter.location in (ParamLocation.BODY, ParamLocation.JSON):
                continue  # POST params need -r request files, not URLs
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
        """Write individual request files for sqlmap -r.

        Injects session cookies and user-agent into each request file
        so sqlmap uses the authenticated session automatically.
        """
        count = 0

        for i, finding in enumerate(self.findings):
            request_text = finding.sqlmap_request()
            if not request_text:
                continue

            # Inject session cookie and user-agent into the request
            if self.session_cookie and "Cookie:" not in request_text:
                request_text = request_text.replace(
                    "Connection: close",
                    f"Cookie: {self.session_cookie}\r\nConnection: close",
                )
            if self.user_agent:
                # Replace the default UA with the authenticated session's UA
                request_text = re.sub(
                    r"User-Agent: [^\r\n]+",
                    f"User-Agent: {self.user_agent}",
                    request_text,
                )

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

    def write_sqlmap_runner(self, path, requests_dir):
        """Write a single executable script that runs sqlmap against all findings.

        HIGH findings first, then MEDIUM. Each command is live (not commented).
        Session cookies, user-agent, and proxy baked into every command.
        Just run: ./run_sqlmap.sh
        """
        extra = " ".join(self.sqlmap_extra_flags)

        # Build session flags — these go into shell variables at the top
        # of the script so quoting is handled once, not per-command
        session_vars = []
        session_refs = []
        if self.session_cookie:
            session_vars.append(f'COOKIE={_shell_quote(self.session_cookie)}')
            session_refs.append('--cookie="$COOKIE"')
        if self.user_agent:
            session_vars.append(f'UA={_shell_quote(self.user_agent)}')
            session_refs.append('--user-agent="$UA"')
        if self.proxy:
            session_vars.append(f'PROXY={_shell_quote(self.proxy)}')
            session_refs.append('--proxy="$PROXY"')
        session_str = " ".join(session_refs)
        all_extra = f"{extra} {session_str}".strip()

        lines = [
            "#!/bin/bash",
            "set -e",
            "",
            "# sqli_recon → sqlmap runner",
            "# Runs sqlmap against all discovered findings, HIGH risk first.",
            "# Session cookies and platform-specific flags are baked in.",
            "#",
            "# Usage: ./run_sqlmap.sh           (run all)",
            "#        ./run_sqlmap.sh --high     (HIGH only)",
            "#        ./run_sqlmap.sh --dry-run  (show commands without running)",
            "",
            *[f'{v}' for v in session_vars],
            "" if session_vars else "# (no session)",
            '# Check sqlmap is available',
            'if ! command -v sqlmap &>/dev/null; then',
            '  if [ -f "$(dirname "$0")/../../.venv/bin/sqlmap" ]; then',
            '    export PATH="$(dirname "$0")/../../.venv/bin:$PATH"',
            '  elif [ -f "$(dirname "$0")/../.venv/bin/sqlmap" ]; then',
            '    export PATH="$(dirname "$0")/../.venv/bin:$PATH"',
            '  else',
            '    echo "sqlmap not found. Install with: pip install sqlmap"',
            '    exit 1',
            '  fi',
            'fi',
            "",
            'DRY_RUN=false',
            'HIGH_ONLY=false',
            'for arg in "$@"; do',
            '  case "$arg" in',
            '    --dry-run) DRY_RUN=true ;;',
            '    --high) HIGH_ONLY=true ;;',
            '  esac',
            'done',
            "",
            'run_cmd() {',
            '  local label="$1"',
            '  shift',
            '  echo ""',
            '  echo "=========================================="',
            '  echo "$label"',
            '  echo "=========================================="',
            '  if [ "$DRY_RUN" = true ]; then',
            '    echo "  $*"',
            '  else',
            '    "$@" || echo "[!] sqlmap exited with code $?"',
            '  fi',
            '}',
            "",
        ]

        if self.sqlmap_notes:
            lines.append("# Platform: " + "; ".join(self.sqlmap_notes))
            lines.append("")

        # Generate commands sorted by risk: HIGH first, then MEDIUM
        cmd_count = 0
        for risk_level in ("HIGH", "MEDIUM"):
            for i, finding in enumerate(self.findings):
                if finding.risk_level != risk_level:
                    continue

                ep = finding.endpoint
                param = finding.parameter
                label = f"[{risk_level}] {ep.method} {ep.base_url} → {param.name} ({param.location.value})"

                if risk_level == "MEDIUM":
                    lines.append('if [ "$HIGH_ONLY" = true ]; then exit 0; fi')
                    lines.append("")
                    # Only add this guard once
                    for j, f2 in enumerate(self.findings):
                        if f2.risk_level == "MEDIUM":
                            if j == i:
                                break
                    # Remove the duplicate guard if we already added it
                    if lines[-2] == 'if [ "$HIGH_ONLY" = true ]; then exit 0; fi':
                        pass  # Keep it
                    break  # Only add the guard once, then fall through

            for i, finding in enumerate(self.findings):
                if finding.risk_level != risk_level:
                    continue

                ep = finding.endpoint
                param = finding.parameter
                confirmed = "CONFIRMED " if finding.score >= 0.90 else ""
                label = f"{confirmed}[{risk_level}] {ep.method} {ep.base_url} → {param.name}"

                if param.location in (ParamLocation.QUERY, ParamLocation.PATH):
                    url = self._build_marked_url(finding)
                    lines.append(f'run_cmd "{label}" sqlmap -u "{url}" --batch {all_extra}')
                elif param.location == ParamLocation.JSON:
                    req_files = [f for f in os.listdir(requests_dir)
                                 if f.startswith(f"{i+1:03d}_")] if os.path.isdir(requests_dir) else []
                    if req_files:
                        req_path = os.path.join(requests_dir, req_files[0])
                        lines.append(f'run_cmd "{label}" sqlmap -r "{req_path}" -p {param.name} --batch {all_extra}')
                elif param.location == ParamLocation.BODY:
                    req_files = [f for f in os.listdir(requests_dir)
                                 if f.startswith(f"{i+1:03d}_")] if os.path.isdir(requests_dir) else []
                    if req_files:
                        req_path = os.path.join(requests_dir, req_files[0])
                        lines.append(f'run_cmd "{label}" sqlmap -r "{req_path}" --batch {all_extra}')
                elif param.location == ParamLocation.HEADER:
                    # Header injection — use --header flag
                    url = ep.base_url
                    lines.append(f'run_cmd "{label}" sqlmap -u "{url}" '
                                 f'--header="{param.name}: test*" --batch {all_extra}')

                cmd_count += 1
                lines.append("")

        lines.append(f'echo ""')
        lines.append(f'echo "Done — {cmd_count} targets tested."')

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
