#!/usr/bin/env python3
"""
skill-audit: Security scanner for AI agent skills.

Scans GitHub repos or local directories containing AI agent skills
(SKILL.md files following the agentskills.io standard) and produces
risk assessment reports.

Usage:
    python3 scan.py https://github.com/someone/cool-skills
    python3 scan.py ./path/to/skills
    python3 scan.py --search "filename:SKILL.md allowed-tools"

Requires: Python 3.8+, git (for GitHub repos)
Optional: GITHUB_TOKEN env var for higher API rate limits
"""

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


@dataclass
class Finding:
    severity: str  # critical, high, medium, low
    category: str
    pattern_id: str
    description: str
    file: str
    line_number: int
    evidence: str

    @property
    def severity_rank(self) -> int:
        return {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(
            self.severity, 4
        )


@dataclass
class SkillReport:
    name: str
    path: str
    files_scanned: int = 0
    findings: list = field(default_factory=list)

    @property
    def risk_score(self) -> int:
        score = 0
        for f in self.findings:
            if f.severity == "critical":
                score += 25
            elif f.severity == "high":
                score += 15
            elif f.severity == "medium":
                score += 5
            elif f.severity == "low":
                score += 1
        return min(score, 100)

    @property
    def verdict(self) -> str:
        score = self.risk_score
        if score >= 60:
            return "DANGEROUS"
        elif score >= 20:
            return "CAUTION"
        return "SAFE"

    @property
    def counts(self) -> dict:
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for f in self.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        return counts


@dataclass
class ScanReport:
    source: str
    skills: list = field(default_factory=list)
    errors: list = field(default_factory=list)

    @property
    def total_findings(self) -> int:
        return sum(len(s.findings) for s in self.skills)

    @property
    def verdict_counts(self) -> dict:
        counts = {"DANGEROUS": 0, "CAUTION": 0, "SAFE": 0}
        for s in self.skills:
            counts[s.verdict] = counts.get(s.verdict, 0) + 1
        return counts


def load_patterns(patterns_path: Optional[str] = None) -> list:
    """Load threat patterns from patterns.json."""
    if patterns_path is None:
        patterns_path = Path(__file__).parent / "patterns.json"
    with open(patterns_path) as f:
        data = json.load(f)
    return data["categories"]


def github_api(endpoint: str, token: Optional[str] = None) -> dict:
    """Make a GitHub API request."""
    url = (
        f"https://api.github.com{endpoint}"
        if not endpoint.startswith("http")
        else endpoint
    )
    headers = {"Accept": "application/vnd.github.v3+json"}
    if token:
        headers["Authorization"] = f"token {token}"
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        if e.code == 403:
            raise SystemExit(
                "GitHub API rate limit hit. Set GITHUB_TOKEN env var for 5000 req/hr."
            )
        raise


def clone_repo(url: str, dest: str) -> None:
    """Shallow clone a GitHub repo."""
    subprocess.run(
        ["git", "clone", "--depth", "1", "--quiet", url, dest],
        check=True,
        capture_output=True,
    )


def find_skills(root: Path) -> list:
    """Find all SKILL.md files in a directory tree."""
    skills = []
    for skill_md in root.rglob("SKILL.md"):
        # Skip test fixtures
        rel = skill_md.relative_to(root)
        if any(p in rel.parts for p in ("test", "tests", "fixtures", "test-fixtures")):
            continue
        skills.append(skill_md.parent)
    return skills


def mark_code_blocks(lines: list, filepath: Path) -> list:
    """Return a set of line numbers (1-indexed) that are inside fenced code blocks.

    In markdown files, content inside ``` fences is documentation/examples,
    not executable instructions. Scanning these produces false positives
    (e.g., threat-patterns.md contains example malicious patterns).
    """
    if filepath.suffix.lower() not in (".md", ".markdown", ".mdx"):
        return set()

    in_block = False
    blocked = set()
    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        if stripped.startswith("```"):
            in_block = not in_block
            blocked.add(i)
            continue
        if in_block:
            blocked.add(i)
    return blocked


def scan_file(filepath: Path, categories: list, skill_root: Path) -> list:
    """Scan a single file against all threat patterns."""
    findings = []
    try:
        content = filepath.read_text(encoding="utf-8", errors="replace")
    except (OSError, UnicodeDecodeError):
        return findings

    lines = content.split("\n")
    rel_path = str(filepath.relative_to(skill_root))
    code_block_lines = mark_code_blocks(lines, filepath)

    for category in categories:
        for pattern_def in category["patterns"]:
            try:
                regex = re.compile(pattern_def["regex"])
            except re.error:
                continue

            for i, line in enumerate(lines, 1):
                # Skip lines inside fenced code blocks (documentation examples)
                if i in code_block_lines:
                    continue

                if regex.search(line):
                    # For context_required patterns, only flag -- don't auto-mark
                    severity = category["severity"]
                    if pattern_def.get("context_required"):
                        severity = "medium"

                    # Skip long base64 pattern in binary-looking files
                    if pattern_def["id"] == "long_base64_string":
                        ext = filepath.suffix.lower()
                        if ext in (
                            ".png", ".jpg", ".svg", ".ico", ".woff", ".woff2",
                            ".ttf", ".eot", ".lock", ".sum",
                        ):
                            continue
                        # Also skip if it looks like a hash or a package lock entry
                        stripped = line.strip()
                        if stripped.startswith('"integrity"') or "sha256" in stripped.lower() or "sha512" in stripped.lower():
                            continue

                    evidence = line.strip()
                    if len(evidence) > 200:
                        evidence = evidence[:200] + "..."

                    findings.append(
                        Finding(
                            severity=severity,
                            category=category["name"],
                            pattern_id=pattern_def["id"],
                            description=pattern_def["description"],
                            file=rel_path,
                            line_number=i,
                            evidence=evidence,
                        )
                    )
                    # One match per pattern per file is enough
                    break

    return findings


def scan_skill(skill_dir: Path, categories: list) -> SkillReport:
    """Scan a single skill directory."""
    name = skill_dir.name
    report = SkillReport(name=name, path=str(skill_dir))

    # Scan all text files in the skill directory
    scannable_extensions = {
        ".md", ".txt", ".sh", ".bash", ".py", ".js", ".ts", ".json",
        ".yaml", ".yml", ".toml", ".cfg", ".ini", ".conf",
    }

    for filepath in skill_dir.rglob("*"):
        if not filepath.is_file():
            continue
        if filepath.suffix.lower() not in scannable_extensions and filepath.name not in (
            "Makefile", "Dockerfile", "Justfile",
        ):
            continue

        report.files_scanned += 1
        findings = scan_file(filepath, categories, skill_dir)
        report.findings.extend(findings)

    # Behavioral analysis: check allowed-tools vs description
    skill_md = skill_dir / "SKILL.md"
    if skill_md.exists():
        report.files_scanned = max(report.files_scanned, 1)
        content = skill_md.read_text(encoding="utf-8", errors="replace")

        # Parse YAML frontmatter
        frontmatter = parse_frontmatter(content)
        if frontmatter:
            allowed_tools = frontmatter.get("allowed-tools", "")
            description = frontmatter.get("description", "").lower()

            # Flag Bash access for skills that sound non-destructive
            benign_keywords = [
                "format", "lint", "style", "review", "read", "analyze",
                "report", "check", "validate", "document",
            ]
            if "Bash" in str(allowed_tools):
                if any(kw in description for kw in benign_keywords):
                    report.findings.append(
                        Finding(
                            severity="medium",
                            category="Excessive Permissions",
                            pattern_id="bash_for_benign_skill",
                            description=f"Skill described as '{description[:60]}...' requests Bash access",
                            file="SKILL.md",
                            line_number=1,
                            evidence=f"allowed-tools: {allowed_tools}",
                        )
                    )

    # Sort findings by severity
    report.findings.sort(key=lambda f: f.severity_rank)

    return report


def parse_frontmatter(content: str) -> Optional[dict]:
    """Parse YAML frontmatter from a SKILL.md file."""
    if not content.startswith("---"):
        return None
    parts = content.split("---", 2)
    if len(parts) < 3:
        return None
    fm = parts[1].strip()
    # Simple key-value parsing (avoid pyyaml dependency)
    result = {}
    current_key = None
    current_value = []
    for line in fm.split("\n"):
        if re.match(r"^\w[\w-]*:", line):
            if current_key:
                result[current_key] = " ".join(current_value).strip()
            key, _, val = line.partition(":")
            current_key = key.strip()
            val = val.strip()
            if val == ">-" or val == ">":
                current_value = []
            else:
                current_value = [val.strip('"').strip("'")]
        elif current_key and line.startswith("  "):
            current_value.append(line.strip())
    if current_key:
        result[current_key] = " ".join(current_value).strip()
    return result


def format_report_markdown(report: ScanReport) -> str:
    """Generate a markdown report."""
    lines = []
    lines.append("# Skill Audit Report")
    lines.append("")
    lines.append(f"**Source**: {report.source}")
    lines.append(f"**Skills scanned**: {len(report.skills)}")
    lines.append(f"**Total findings**: {report.total_findings}")
    lines.append("")

    # Summary table
    vc = report.verdict_counts
    lines.append("## Risk Distribution")
    lines.append("")
    lines.append("| Verdict | Count | % |")
    lines.append("|---|---|---|")
    total = len(report.skills) or 1
    for verdict in ["DANGEROUS", "CAUTION", "SAFE"]:
        count = vc[verdict]
        pct = count / total * 100
        lines.append(f"| {verdict} | {count} | {pct:.1f}% |")
    lines.append("")

    # Most common issues
    pattern_counts = {}
    for skill in report.skills:
        for f in skill.findings:
            key = f"{f.category}: {f.description}"
            pattern_counts[key] = pattern_counts.get(key, 0) + 1
    if pattern_counts:
        lines.append("## Most Common Issues")
        lines.append("")
        sorted_patterns = sorted(pattern_counts.items(), key=lambda x: -x[1])
        for pattern, count in sorted_patterns[:10]:
            lines.append(f"- **{count}** skills: {pattern}")
        lines.append("")

    # Per-skill details
    # Show DANGEROUS and CAUTION first
    flagged = [s for s in report.skills if s.verdict != "SAFE"]
    if flagged:
        lines.append("## Flagged Skills")
        lines.append("")
        for skill in sorted(flagged, key=lambda s: -s.risk_score):
            lines.append(f"### {skill.name}")
            lines.append("")
            lines.append(
                f"**Verdict**: {skill.verdict} | "
                f"**Risk Score**: {skill.risk_score}/100 | "
                f"**Files**: {skill.files_scanned}"
            )
            counts = skill.counts
            lines.append(
                f"**Findings**: {counts['critical']} critical, "
                f"{counts['high']} high, {counts['medium']} medium, "
                f"{counts['low']} low"
            )
            lines.append("")

            if skill.findings:
                lines.append("| Severity | Category | File | Line | Evidence |")
                lines.append("|---|---|---|---|---|")
                for f in skill.findings:
                    sev = f.severity.upper()
                    evidence = f.evidence.replace("|", "\\|")
                    if len(evidence) > 80:
                        evidence = evidence[:80] + "..."
                    lines.append(
                        f"| {sev} | {f.category} | `{f.file}` | {f.line_number} | `{evidence}` |"
                    )
                lines.append("")

    # Safe skills summary
    safe = [s for s in report.skills if s.verdict == "SAFE"]
    if safe:
        lines.append("## Safe Skills")
        lines.append("")
        for skill in safe:
            lines.append(f"- {skill.name} ({skill.files_scanned} files scanned)")
        lines.append("")

    # Errors
    if report.errors:
        lines.append("## Errors")
        lines.append("")
        for err in report.errors:
            lines.append(f"- {err}")
        lines.append("")

    lines.append("---")
    lines.append(
        "*Generated by [skill-audit](https://github.com/ArielSmoliar/skill-audit) "
        "using threat patterns from [safe-agent](https://github.com/ArielSmoliar/safe-agent)*"
    )

    return "\n".join(lines)


def format_report_json(report: ScanReport) -> str:
    """Generate a JSON report."""
    data = {
        "source": report.source,
        "skills_scanned": len(report.skills),
        "total_findings": report.total_findings,
        "verdict_counts": report.verdict_counts,
        "skills": [],
    }
    for skill in report.skills:
        skill_data = {
            "name": skill.name,
            "path": skill.path,
            "verdict": skill.verdict,
            "risk_score": skill.risk_score,
            "files_scanned": skill.files_scanned,
            "findings": [
                {
                    "severity": f.severity,
                    "category": f.category,
                    "pattern_id": f.pattern_id,
                    "description": f.description,
                    "file": f.file,
                    "line_number": f.line_number,
                    "evidence": f.evidence,
                }
                for f in skill.findings
            ],
        }
        data["skills"].append(skill_data)
    return json.dumps(data, indent=2)


def scan_local(path: str, categories: list) -> ScanReport:
    """Scan a local directory for skills."""
    root = Path(path).resolve()
    if not root.exists():
        raise SystemExit(f"Path not found: {root}")

    report = ScanReport(source=str(root))

    skills = find_skills(root)
    if not skills:
        # Maybe the path itself is a skill directory
        if (root / "SKILL.md").exists():
            skills = [root]
        else:
            report.errors.append(f"No SKILL.md files found in {root}")
            return report

    for skill_dir in skills:
        skill_report = scan_skill(skill_dir, categories)
        report.skills.append(skill_report)

    return report


def scan_github(url: str, categories: list) -> ScanReport:
    """Scan a GitHub repo for skills."""
    # Parse owner/repo from URL
    url = url.rstrip("/")
    if url.startswith("https://github.com/"):
        parts = url.replace("https://github.com/", "").split("/")
    elif "/" in url and not url.startswith("/"):
        parts = url.split("/")
    else:
        raise SystemExit(f"Cannot parse GitHub URL: {url}")

    if len(parts) < 2:
        raise SystemExit(f"Cannot parse GitHub URL: {url}")

    owner, repo = parts[0], parts[1]

    tmpdir = tempfile.mkdtemp(prefix="skill-audit-")
    try:
        clone_url = f"https://github.com/{owner}/{repo}.git"
        print(f"Cloning {owner}/{repo}...", file=sys.stderr)
        clone_repo(clone_url, tmpdir)
        report = scan_local(tmpdir, categories)
        report.source = f"https://github.com/{owner}/{repo}"
        return report
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def search_github(query: str, categories: list, token: Optional[str] = None, limit: int = 50) -> ScanReport:
    """Search GitHub for repos with skills and scan them."""
    report = ScanReport(source=f"GitHub search: {query}")

    # Search for code matching the query
    encoded_query = urllib.parse.quote(query)
    search_url = f"/search/code?q={encoded_query}&per_page={min(limit, 100)}"

    print(f"Searching GitHub: {query}...", file=sys.stderr)
    try:
        results = github_api(search_url, token)
    except Exception as e:
        report.errors.append(f"Search failed: {e}")
        return report

    # Deduplicate by repo
    repos_seen = set()
    repos_to_scan = []
    for item in results.get("items", []):
        repo_full = item["repository"]["full_name"]
        if repo_full not in repos_seen:
            repos_seen.add(repo_full)
            repos_to_scan.append(repo_full)

    print(f"Found {len(repos_to_scan)} repos to scan.", file=sys.stderr)

    for i, repo_full in enumerate(repos_to_scan[:limit], 1):
        print(f"[{i}/{len(repos_to_scan)}] Scanning {repo_full}...", file=sys.stderr)
        try:
            sub_report = scan_github(f"https://github.com/{repo_full}", categories)
            report.skills.extend(sub_report.skills)
            report.errors.extend(sub_report.errors)
        except Exception as e:
            report.errors.append(f"Failed to scan {repo_full}: {e}")

    return report


def main():
    parser = argparse.ArgumentParser(
        description="Scan AI agent skills for security threats.",
        epilog="Examples:\n"
        "  python3 scan.py https://github.com/someone/skills\n"
        "  python3 scan.py ./path/to/skills\n"
        '  python3 scan.py --search "filename:SKILL.md allowed-tools"\n',
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "target",
        nargs="?",
        help="GitHub repo URL or local path to scan",
    )
    parser.add_argument(
        "--search",
        metavar="QUERY",
        help="Search GitHub for repos matching query and scan them",
    )
    parser.add_argument(
        "--format",
        choices=["markdown", "json"],
        default="markdown",
        help="Output format (default: markdown)",
    )
    parser.add_argument(
        "--output", "-o",
        metavar="FILE",
        help="Write report to file instead of stdout",
    )
    parser.add_argument(
        "--patterns",
        metavar="FILE",
        help="Path to custom patterns.json",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=50,
        help="Max repos to scan in search mode (default: 50)",
    )
    args = parser.parse_args()

    if not args.target and not args.search:
        parser.print_help()
        sys.exit(1)

    categories = load_patterns(args.patterns)
    token = os.environ.get("GITHUB_TOKEN")
    if not token:
        # Try gh CLI
        try:
            result = subprocess.run(
                ["gh", "auth", "token"], capture_output=True, text=True
            )
            if result.returncode == 0:
                token = result.stdout.strip()
        except FileNotFoundError:
            pass

    if args.search:
        report = search_github(args.search, categories, token, args.limit)
    elif args.target:
        target = args.target
        if target.startswith("https://github.com/") or target.startswith("github.com/"):
            report = scan_github(target, categories)
        elif "/" in target and not os.path.exists(target):
            # Might be owner/repo shorthand
            report = scan_github(f"https://github.com/{target}", categories)
        else:
            report = scan_local(target, categories)

    if args.format == "json":
        output = format_report_json(report)
    else:
        output = format_report_markdown(report)

    if args.output:
        Path(args.output).write_text(output)
        print(f"Report written to {args.output}", file=sys.stderr)
    else:
        print(output)

    # Exit with non-zero if any DANGEROUS skills found
    if report.verdict_counts.get("DANGEROUS", 0) > 0:
        sys.exit(1)


if __name__ == "__main__":
    main()
