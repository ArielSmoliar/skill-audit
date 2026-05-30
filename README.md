# skill-audit

Security scanner for AI agent skills. Scans GitHub repos or local directories for prompt injection, data exfiltration, credential theft, and malicious patterns in SKILL.md files and their supporting scripts.

Think `npm audit` but for AI agent skills.

## Why

[Snyk's ToxicSkills research](https://snyk.io) found that **36.82% of AI agent skills** have at least one security flaw. Every time you install a skill, you're trusting someone else's instructions inside your codebase, shell, and cloud credentials.

skill-audit lets you check before you install -- or scan the entire ecosystem at once.

## Install

```bash
git clone https://github.com/ArielSmoliar/skill-audit.git
cd skill-audit
```

No dependencies beyond Python 3.8+ and git. Optional: set `GITHUB_TOKEN` for higher GitHub API rate limits (5000 req/hr vs 60).

## Usage

### Scan a GitHub repo

```bash
python3 scan.py https://github.com/someone/cool-skills
```

### Scan a local directory

```bash
python3 scan.py ./path/to/skills
```

### Scan with owner/repo shorthand

```bash
python3 scan.py someone/cool-skills
```

### Search GitHub and scan matching repos

```bash
python3 scan.py --search "filename:SKILL.md allowed-tools"
python3 scan.py --search "filename:SKILL.md path:skills" --limit 100
```

### Output formats

```bash
python3 scan.py ./skills                          # Markdown (default)
python3 scan.py ./skills --format json            # JSON
python3 scan.py ./skills -o report.md             # Write to file
python3 scan.py ./skills --format json -o report.json
```

## Example Output

```
# Skill Audit Report

**Source**: https://github.com/someone/cool-skills
**Skills scanned**: 12
**Total findings**: 7

## Risk Distribution

| Verdict | Count | % |
|---|---|---|
| DANGEROUS | 1 | 8.3% |
| CAUTION | 2 | 16.7% |
| SAFE | 9 | 75.0% |

## Flagged Skills

### deploy-helper

**Verdict**: DANGEROUS | **Risk Score**: 85/100 | **Files**: 2
**Findings**: 3 critical, 0 high, 2 medium, 0 low

| Severity | Category | File | Line | Evidence |
|---|---|---|---|---|
| CRITICAL | Credential Harvesting | SKILL.md | 20 | `cat ~/.aws/credentials` |
| CRITICAL | Data Exfiltration | scripts/setup.sh | 14 | `curl -d @/tmp/creds https://...` |
| CRITICAL | Credential Harvesting | scripts/setup.sh | 8 | `cat ~/.ssh/id_rsa | base64` |
| MEDIUM | Excessive Permissions | SKILL.md | 6 | `allowed-tools: Read Write Bash Glob` |
```

## What It Checks

skill-audit scans against 35+ threat patterns across 7 categories:

| Category | Severity | What it catches |
|---|---|---|
| Prompt Injection | Critical | Instruction overrides, SYSTEM impersonation, authority escalation, conditional triggers |
| Data Exfiltration | Critical | URL-encoded exfil, DNS exfil, clipboard theft, POST with local data |
| Credential Harvesting | Critical | Reading .env, AWS, SSH, GCP, Azure, Docker, npm credentials |
| Obfuscation | High | Base64/hex decode to exec, variable indirection, encoded payloads |
| Persistence | High | Shell config modification, git hook writes, cron jobs, agent config changes |
| Hook Hijacking | High | Silent network calls, environment-conditional execution, backgrounded uploads |
| Excessive Permissions | Medium | Bash/Write/Network access unjustified by skill description |

Patterns are defined in `patterns.json` and sourced from [safe-agent](https://github.com/ArielSmoliar/safe-agent)'s threat research.

## How It Works

1. **Discovery** -- finds all `SKILL.md` files in the target (skips test fixtures)
2. **Static analysis** -- matches each file against the threat pattern regexes
3. **Behavioral analysis** -- compares `allowed-tools` in frontmatter against the skill's stated purpose
4. **Code block filtering** -- skips content inside fenced code blocks in markdown (documentation examples, not real threats)
5. **Scoring** -- critical = 25pts, high = 15pts, medium = 5pts, low = 1pt (capped at 100)
6. **Verdict** -- DANGEROUS (60+), CAUTION (20-59), SAFE (0-19)

## Custom Patterns

Supply your own patterns file:

```bash
python3 scan.py ./skills --patterns my-patterns.json
```

See `patterns.json` for the schema.

## Exit Codes

- `0` -- no DANGEROUS skills found
- `1` -- at least one DANGEROUS skill found (useful for CI gating)

## Relationship to safe-agent

[safe-agent](https://github.com/ArielSmoliar/safe-agent) is a set of defensive skills that protect your agent at runtime (budget limits, tool restrictions, behavioral anomaly detection). skill-audit is an analytical tool that scans skills before you install them -- or scans the entire ecosystem. They share threat pattern research but serve different purposes.

## License

MIT
