# Domain Checker

Automates the morning check of customer domains. For every domain in `domains.csv` it checks:

| Check | How | Problem if |
|---|---|---|
| Resolves | one DNS A-record lookup (dnspython) | NXDOMAIN / no record / timeout → **CRITICAL** |
| CNAME | the first CNAME in the chain vs `expected_cname` (case and trailing dot ignored) | different or missing → **WARNING** |
| SSL | TLS handshake with full verification (chain + hostname); if it fails, the cert is fetched again without verification to still read its expiry | expired, self-signed, wrong host, untrusted → **CRITICAL**; expires in < 14 days → **WARNING** |
| Responds | one HTTPS GET to `/` | no response or 5xx → **CRITICAL**. A 4xx (e.g. 403 from bot protection) still counts as responding |

Output: a summary with problems at the top, saved as `results/YYYY-MM-DD.md` (human) and `.json` (machine).
Problems that were not there in the previous run are marked **NEW**, and domains that were fixed are listed.
An alert (Telegram and/or email) is sent only when something needs attention.

## Setup (once)

```bash
pip install -r requirements.txt
```
Python 3.10+ (tested on 3.12/3.13, Windows and Linux).

## Run

```bash
python check.py              # check, save results, alert if needed
python check.py --no-alert   # same, but never send an alert
python check.py --csv my.csv # use another list
python -m pytest -q          # 17 offline tests
```

## Run it every morning (pick one)

**A. GitHub Actions — runs even when the laptop is off (recommended).**
Push this folder to a GitHub repo. `.github/workflows/daily-check.yml` runs at 08:00 Malaysia time,
runs the tests, runs the check and commits the day's file to `results/`. Test it now via
*Actions → Daily domain check → Run workflow*. For alerts add repo secrets
`TELEGRAM_BOT_TOKEN` and `TELEGRAM_CHAT_ID` (*Settings → Secrets and variables → Actions*).

**B. Windows Task Scheduler — runs on this laptop.**
```powershell
powershell -ExecutionPolicy Bypass -File setup_schedule.ps1   # daily 08:00
Start-ScheduledTask -TaskName DomainCheck                      # run now to test
```
Console output is appended to `results/log.txt`. If the laptop was off at 08:00 it runs when it is back on.

## Alerts (bonus)

Copy `.env.example` to `.env` and fill in a channel (the file is git-ignored):
- **Telegram:** create a bot with @BotFather → token; send the bot a message; open
  `https://api.telegram.org/bot<TOKEN>/getUpdates` → `chat.id`.
- **Email:** SMTP settings (Gmail: `smtp.gmail.com`, port 587, an App Password).

No channel configured → the run still works and just says so. All OK → nothing is sent.

## Extras (my idea)
- **NEW / FIXED tracking** against the previous day's result, so the team sees what changed today.
- **Expiry early-warning** (< 14 days) before a certificate actually breaks.
- **Offline test suite**, including real local TLS servers with expired / self-signed / wrong-host certificates.

## Files
```
check.py            checks + report + main
alerts.py           Telegram / email
domains.csv         input list
tests/              offline tests
run_daily.bat, setup_schedule.ps1   Windows schedule
.github/workflows/daily-check.yml   GitHub schedule
CLAUDE.md           instructions for Claude Code
results/            one .md + .json per day
```
