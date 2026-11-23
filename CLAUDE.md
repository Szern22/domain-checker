# CLAUDE.md — Domain Checker

Project instructions for Claude Code. Read this before changing anything.

## What this project is
A daily health check for customer domains (Vykon assignment). For each row in `domains.csv`
it checks DNS resolution, CNAME vs `expected_cname`, SSL validity + days to expiry, and
whether the site responds. Problems are printed first, saved to `results/YYYY-MM-DD.md/.json`,
and sent as a Telegram/email alert only when something needs attention.

## Files
- `check.py` — all checks, evaluation, report, main(). One function per check.
- `alerts.py` — Telegram + email sending, `.env` loading. Alerts never crash the run.
- `domains.csv` — input. Columns: `domain,expected_cname` (empty = no CNAME comparison).
- `tests/test_check.py` — offline tests (fake DNS/HTTP + real local TLS servers).
- `run_daily.bat` + `setup_schedule.ps1` — Windows Task Scheduler (local laptop).
- `.github/workflows/daily-check.yml` — same schedule on GitHub Actions (08:00 MYT).

## Rules
- Python 3.10+, standard library + `dnspython` + `cryptography` only. Keep it simple and readable:
  the owner must be able to explain every line in an interview.
- Be light on the target sites: one DNS query, at most two TLS handshakes, one HTTP GET per domain.
  Every network call has a timeout (`TIMEOUT` in check.py).
- One domain failing must never stop the others; catch errors per check and report them as issues.
- Severity: CRITICAL = broken now (no DNS, bad cert, no response, 5xx).
  WARNING = needs attention (CNAME mismatch, cert < `WARN_DAYS` days).
  HTTP 4xx is NOT a problem: the site responded (often 403 = bot protection). Only no response / 5xx.
- Never commit secrets. Tokens live in `.env` (git-ignored) or GitHub Secrets.
- Console output stays ASCII (Windows consoles); markdown/JSON files are UTF-8.

## Workflow for every change
1. Plan first and show the plan before editing.
2. Add or update a test in `tests/test_check.py` for the new behaviour.
3. Run `python -m pytest -q` — all must pass.
4. Run `python check.py --no-alert` and show the output; confirm the expected problems still appear:
   microsoft = CNAME mismatch, expired/wrong.host/self-signed badssl = SSL invalid,
   this-domain-does-not-exist = does not resolve; cloudflare/github/wikipedia = OK.
5. Update README.md if usage changed.
