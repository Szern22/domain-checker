# Build log (facts for your learning note)

This project was built by Claude (Cowork) on 23 Nov 2026, not in the Claude Code CLI.
Things that went wrong or needed correcting during the build:

1. **Test certificates rejected by Python 3.13.** The first SSL tests failed with
   "Missing Authority Key Identifier". The checker code was fine; the generated test
   certificates lacked SubjectKeyIdentifier/AuthorityKeyIdentifier, which Python 3.13's
   stricter default verification requires. Fixed in the test helper.
2. **Batch-file fallback bug.** The first `run_daily.bat` used `where py && (...) || (...)`,
   which would re-run the check with `python` whenever the check itself returned an error.
   Replaced with an explicit if/else.
3. **Confusing output.** Expired certificates were first shown as "-590 days"; changed to
   "expired ... 590 days ago".
4. **No internet in the build sandbox.** The real domains could not be reached while building,
   so the logic was verified with simulated results and local TLS servers. The real run must be
   done on the laptop / GitHub Actions and compared against the expected table in CLAUDE.md.
5. **False alarms from slow servers (found in the first real run).** On the laptop, two runs
   gave a different false "timed out" each time (first expired.badssl.com's SSL check, then
   wrong.host.badssl.com's HTTP check). The test sites are sometimes slow. Fix: retry once on
   a timeout only (`retry_on_timeout` in check.py), with 3 new tests.
6. **403 treated as a problem.** After several runs in a few minutes, www.github.com started
   answering HTTP 403 (bot/rate protection) and was flagged as WARNING although the site was up.
   The requirement is "does the site respond", and a 403 is a response. Changed: only no response
   or 5xx is a problem; the HTTP code is still shown in the report.
