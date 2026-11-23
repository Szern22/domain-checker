"""Daily domain health check.

Reads domains.csv and, for each domain, checks:
  1. DNS    - does the name resolve?
  2. CNAME  - if expected_cname is set, does the domain's CNAME point there?
  3. SSL    - is the certificate valid, and how many days until it expires?
  4. HTTP   - does the site respond?

Prints a summary with problems at the top, saves results/YYYY-MM-DD.md and .json,
and (if configured) sends a Telegram / email alert when something needs attention.

Usage:
    python check.py                      # normal run
    python check.py --csv other.csv      # different input
    python check.py --no-alert           # never send alerts (e.g. while testing)
"""

import argparse
import csv
import datetime as dt
import json
import socket
import ssl
import sys
import urllib.error
import urllib.request
from pathlib import Path

import dns.exception
import dns.resolver
from cryptography import x509

import alerts

TIMEOUT = 8            # seconds, for every network call
WARN_DAYS = 14         # warn when a certificate expires within this many days
USER_AGENT = "Mozilla/5.0 (domain-checker; daily health check)"

CRITICAL, WARNING, OK = "CRITICAL", "WARNING", "OK"
SEVERITY_ORDER = {CRITICAL: 0, WARNING: 1, OK: 2}


# --------------------------------------------------------------------------- input

def read_domains(path):
    """Return a list of (domain, expected_cname) from the CSV. Blank lines are skipped."""
    rows = []
    with open(path, newline="", encoding="utf-8-sig") as f:
        for row in csv.DictReader(f):
            domain = (row.get("domain") or "").strip()
            if domain:
                rows.append((domain, (row.get("expected_cname") or "").strip()))
    return rows


def normalize(name):
    """DNS names are case-insensitive and may end with a dot: 'GitHub.com.' == 'github.com'."""
    return name.strip().rstrip(".").lower()


# --------------------------------------------------------------------------- checks

def check_dns(domain):
    """One A-record lookup. dnspython follows the CNAME chain for us and records it.

    Returns {"resolves": bool, "ips": [...], "cname": first CNAME target or None,
             "chain": [all CNAME targets], "error": str or None}
    """
    result = {"resolves": False, "ips": [], "cname": None, "chain": [], "error": None}
    resolver = dns.resolver.Resolver()
    resolver.lifetime = TIMEOUT
    try:
        answer = resolver.resolve(domain, "A")
    except dns.resolver.NXDOMAIN:
        result["error"] = "domain does not exist (NXDOMAIN)"
        return result
    except dns.resolver.NoAnswer:
        result["error"] = "no A record"
        return result
    except dns.exception.Timeout:
        result["error"] = "DNS lookup timed out"
        return result
    except dns.exception.DNSException as e:
        result["error"] = f"DNS error: {e.__class__.__name__}"
        return result

    result["resolves"] = True
    result["ips"] = [r.address for r in answer]
    # chaining_result.cnames = the CNAME records followed to reach the A record, in order
    chain = [normalize(str(rrset[0].target)) for rrset in answer.chaining_result.cnames]
    result["chain"] = chain
    result["cname"] = chain[0] if chain else None
    return result


def _is_timeout(exc):
    """True if the error is a timeout (urllib wraps timeouts inside URLError.reason)."""
    return isinstance(exc, (socket.timeout, TimeoutError)) or \
        isinstance(getattr(exc, "reason", None), (socket.timeout, TimeoutError))


def retry_on_timeout(fn, *args):
    """Call fn once; if it times out, try exactly one more time.
    Public test sites are sometimes slow for a few seconds - one retry avoids false alarms
    while keeping the requests light (at most one extra request per domain)."""
    try:
        return fn(*args)
    except Exception as e:
        if not _is_timeout(e):
            raise
        return fn(*args)


def _cert_expiry(der_bytes):
    cert = x509.load_der_x509_certificate(der_bytes)
    try:
        return cert.not_valid_after_utc
    except AttributeError:  # older cryptography versions
        return cert.not_valid_after.replace(tzinfo=dt.timezone.utc)


def _fetch_cert_unverified(domain, port=443):
    """Get the certificate without verifying it, so we can still read its expiry date."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection((domain, port), timeout=TIMEOUT) as sock:
        with ctx.wrap_socket(sock, server_hostname=domain) as s:
            return s.getpeercert(binary_form=True)


# OpenSSL verify codes -> plain-English reason
SSL_REASONS = {
    10: "certificate has expired",
    18: "self-signed certificate (not trusted)",
    19: "self-signed certificate in chain (not trusted)",
    20: "certificate issuer not trusted",
    62: "certificate does not match the domain name",
}


def check_ssl(domain, now=None, port=443, cafile=None):
    """Returns {"valid": bool, "days_left": int or None, "expires": iso str or None, "error": str or None}
    (port and cafile exist only so the tests can use a local test server.)"""
    now = now or dt.datetime.now(dt.timezone.utc)
    result = {"valid": False, "days_left": None, "expires": None, "error": None}
    ctx = ssl.create_default_context(cafile=cafile)  # verifies chain + hostname, like a browser

    def handshake():
        with socket.create_connection((domain, port), timeout=TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as s:
                return s.getpeercert(binary_form=True)

    try:
        der = retry_on_timeout(handshake)
        result["valid"] = True
    except ssl.SSLCertVerificationError as e:
        result["error"] = SSL_REASONS.get(e.verify_code, e.verify_message or str(e))
        try:
            der = retry_on_timeout(_fetch_cert_unverified, domain, port)
        except Exception:
            der = None
    except (socket.timeout, TimeoutError):
        result["error"] = "SSL connection timed out"
        return result
    except (ssl.SSLError, OSError) as e:
        result["error"] = f"SSL connection failed: {e.__class__.__name__}"
        return result

    if der:
        expires = _cert_expiry(der)
        result["expires"] = expires.date().isoformat()
        result["days_left"] = (expires - now).days
    return result


def check_http(domain):
    """One GET request to https://domain/. Certificate problems are reported by check_ssl,
    so here we skip verification and only ask: does the server answer?

    Returns {"status": int or None, "error": str or None}
    """
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    req = urllib.request.Request(f"https://{domain}/", headers={"User-Agent": USER_AGENT})

    def get():
        with urllib.request.urlopen(req, timeout=TIMEOUT, context=ctx) as resp:
            return resp.status

    try:
        return {"status": retry_on_timeout(get), "error": None}
    except urllib.error.HTTPError as e:      # server answered, but with 4xx/5xx
        return {"status": e.code, "error": None}
    except (urllib.error.URLError, socket.timeout, TimeoutError, OSError) as e:
        reason = getattr(e, "reason", e)
        return {"status": None, "error": f"no response ({reason})"}


# --------------------------------------------------------------------------- evaluate

def evaluate(domain, expected_cname, dns_fn=check_dns, ssl_fn=check_ssl, http_fn=check_http):
    """Run all checks for one domain and turn the raw results into a list of issues.

    The *_fn arguments let tests pass in fake checks (no network needed).
    """
    issues = []  # list of (severity, message)
    res = {"domain": domain, "expected_cname": expected_cname or None}

    d = dns_fn(domain)
    res["dns"] = d
    if not d["resolves"]:
        issues.append((CRITICAL, f"Does not resolve: {d['error']}"))
        res["ssl"] = res["http"] = None  # nothing else can be checked
    else:
        if expected_cname:
            actual = d["cname"]
            if actual is None:
                issues.append((WARNING, f"CNAME mismatch: expected {expected_cname}, but there is no CNAME (points directly to an IP)"))
            elif actual != normalize(expected_cname):
                issues.append((WARNING, f"CNAME mismatch: expected {expected_cname}, actual {actual}"))

        s = ssl_fn(domain)
        res["ssl"] = s
        if not s["valid"]:
            msg = f"SSL invalid: {s['error']}"
            if s["days_left"] is not None and s["days_left"] < 0:
                msg += f" (expired {s['expires']}, {-s['days_left']} days ago)"
            elif s["expires"]:
                msg += f" (expires {s['expires']})"
            issues.append((CRITICAL, msg))
        elif s["days_left"] is not None and s["days_left"] < WARN_DAYS:
            issues.append((WARNING, f"SSL expires soon: {s['days_left']} days left ({s['expires']})"))

        h = http_fn(domain)
        res["http"] = h
        if h["status"] is None:
            issues.append((CRITICAL, f"Site not responding: {h['error']}"))
        elif h["status"] >= 500:
            issues.append((CRITICAL, f"Site error: HTTP {h['status']}"))
        # 4xx (e.g. 403) is NOT flagged: the server did respond. Sites often answer 403 to
        # automated requests (bot protection), so flagging it would cause false alarms.
        # The code is still shown in the report.

    res["issues"] = [{"severity": sev, "message": msg} for sev, msg in issues]
    res["status"] = min((sev for sev, _ in issues), key=SEVERITY_ORDER.get, default=OK)
    return res


def mark_new_issues(results, previous):
    """Compare with the previous run: flag issues that were not there last time,
    and list domains whose problems were fixed."""
    prev = {r["domain"]: {i["message"] for i in r["issues"]} for r in (previous or [])}
    resolved = []
    for r in results:
        old = prev.get(r["domain"])
        for i in r["issues"]:
            i["new"] = previous is not None and (old is None or i["message"] not in old)
        if old and r["status"] == OK:
            resolved.append(r["domain"])
    return resolved


# --------------------------------------------------------------------------- output

def summary_line(r):
    s, h = r.get("ssl"), r.get("http")
    parts = []
    if r["dns"]["resolves"]:
        parts.append(f"CNAME {r['dns']['cname'] or '-'}")
        if s and s["days_left"] is not None:
            parts.append(f"SSL {s['days_left']}d")
        if h and h["status"]:
            parts.append(f"HTTP {h['status']}")
    return ", ".join(parts)


def render_text(results, resolved, run_time):
    """Plain-text report (ASCII only, so it prints fine in any Windows console)."""
    bad = [r for r in results if r["status"] != OK]
    good = [r for r in results if r["status"] == OK]
    out = [f"Domain check - {run_time:%Y-%m-%d %H:%M}",
           f"{len(results)} domains: {sum(r['status'] == CRITICAL for r in results)} critical, "
           f"{sum(r['status'] == WARNING for r in results)} warning, {len(good)} ok", ""]
    if bad:
        out.append("NEEDS ATTENTION")
        for r in bad:
            out.append(f"  [{r['status']}] {r['domain']}")
            for i in r["issues"]:
                tag = " (NEW)" if i.get("new") else ""
                out.append(f"      - {i['message']}{tag}")
        out.append("")
    if resolved:
        out.append("FIXED SINCE LAST RUN: " + ", ".join(resolved))
        out.append("")
    if good:
        out.append("OK")
        for r in good:
            out.append(f"  [OK] {r['domain']:<28} {summary_line(r)}")
    return "\n".join(out)


def render_markdown(results, resolved, run_time):
    bad = [r for r in results if r["status"] != OK]
    good = [r for r in results if r["status"] == OK]
    out = [f"# Domain check - {run_time:%Y-%m-%d %H:%M}", "",
           f"**{len(results)} domains:** {sum(r['status'] == CRITICAL for r in results)} critical, "
           f"{sum(r['status'] == WARNING for r in results)} warning, {len(good)} ok", ""]
    if bad:
        out += ["## Needs attention", "", "| Status | Domain | Problem |", "|---|---|---|"]
        for r in bad:
            for i in r["issues"]:
                tag = " **NEW**" if i.get("new") else ""
                out.append(f"| {i['severity']} | {r['domain']} | {i['message']}{tag} |")
        out.append("")
    if resolved:
        out += ["## Fixed since last run", "", ", ".join(resolved), ""]
    out += ["## All domains", "", "| Domain | Status | Resolves | CNAME | SSL days left | HTTP |",
            "|---|---|---|---|---|---|"]
    for r in results:
        d, s, h = r["dns"], r.get("ssl") or {}, r.get("http") or {}
        out.append(f"| {r['domain']} | {r['status']} | {'yes' if d['resolves'] else 'no'} | "
                   f"{d['cname'] or '-'} | {s.get('days_left', '-') if s.get('days_left') is not None else '-'} | "
                   f"{h.get('status') or '-'} |")
    return "\n".join(out) + "\n"


def load_previous(out_dir, today):
    """Most recent JSON result from an earlier day, or None."""
    files = sorted(p for p in Path(out_dir).glob("*.json") if p.stem < today)
    if not files:
        return None
    try:
        return json.loads(files[-1].read_text(encoding="utf-8"))["results"]
    except (ValueError, KeyError):
        return None


# --------------------------------------------------------------------------- main

def main(argv=None):
    here = Path(__file__).resolve().parent
    p = argparse.ArgumentParser(description="Daily domain health check")
    p.add_argument("--csv", default=str(here / "domains.csv"))
    p.add_argument("--out-dir", default=str(here / "results"))
    p.add_argument("--no-alert", action="store_true", help="do not send Telegram/email alerts")
    args = p.parse_args(argv)

    run_time = dt.datetime.now()
    today = run_time.strftime("%Y-%m-%d")
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    results = [evaluate(domain, cname) for domain, cname in read_domains(args.csv)]
    results.sort(key=lambda r: (SEVERITY_ORDER[r["status"]], r["domain"]))
    resolved = mark_new_issues(results, load_previous(out_dir, today))

    text = render_text(results, resolved, run_time)
    print(text)

    (out_dir / f"{today}.md").write_text(render_markdown(results, resolved, run_time), encoding="utf-8")
    (out_dir / f"{today}.json").write_text(json.dumps(
        {"run_time": run_time.isoformat(timespec="seconds"), "results": results, "resolved": resolved},
        indent=2), encoding="utf-8")
    print(f"\nSaved {out_dir / (today + '.md')}")

    problems = [r for r in results if r["status"] != OK]
    if problems and not args.no_alert:
        alerts.load_env(here / ".env")
        sent = alerts.send_all(text)
        print("Alert sent via: " + ", ".join(sent) if sent else "Alert not sent (no channel configured, see README)")
    elif not problems:
        print("All domains OK - no alert sent.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
