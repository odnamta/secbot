# Bounty Pool

Findings from SecBot scans, organized for human review and batch submission.

## Workflow
1. SecBot scans target → findings saved to `pending/`
2. Dio reviews findings → moves to `submitted/` or `rejected/`
3. After platform response → moves to `accepted/` or stays in `submitted/`
4. Run `secbot outcome <id> accepted|duplicate|informative` to feed learning loop

## Directory Structure
- `pending/` — Findings awaiting human review
- `submitted/` — Submitted to bounty platform, awaiting response
- `accepted/` — Accepted findings (with payout info)
- `rejected/` — Not submitted (FP, informational, duplicate)

## Finding File Format
Each file: `YYYY-MM-DD-<program>-<vuln-type>.md`
Contains: title, severity, evidence, reproduction steps, impact, fix suggestion.
