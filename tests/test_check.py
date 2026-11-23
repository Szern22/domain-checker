"""Tests that run without internet.

- evaluate() is tested with fake DNS/SSL/HTTP results (one test per real-world problem).
- check_ssl() is tested against real local TLS servers using generated certificates:
  valid, expired, self-signed and wrong-hostname.

Run:  python -m pytest -q
"""

import datetime as dt
import socket
import ssl
import sys
import threading
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import check  # noqa: E402

# ----------------------------------------------------------------------------- fakes

def dns_ok(cname=None):
    return lambda d: {"resolves": True, "ips": ["1.2.3.4"], "cname": cname,
                      "chain": [cname] if cname else [], "error": None}


def dns_fail(d):
    return {"resolves": False, "ips": [], "cname": None, "chain": [],
            "error": "domain does not exist (NXDOMAIN)"}


def ssl_ok(days=90):
    return lambda d: {"valid": True, "days_left": days, "expires": "2027-01-01", "error": None}


def ssl_bad(error, days):
    return lambda d: {"valid": False, "days_left": days, "expires": "2020-01-01", "error": error}


def http(status):
    return lambda d: {"status": status, "error": None if status else "no response (timed out)"}


def run(expected="", dns=dns_ok(), ssl_=ssl_ok(), http_=http(200)):
    return check.evaluate("example.com", expected, dns, ssl_, http_)


# ----------------------------------------------------------------------------- evaluate()

def test_healthy_domain_is_ok():
    r = run()
    assert r["status"] == "OK" and r["issues"] == []


def test_cname_match_ignores_case_and_trailing_dot():
    assert run("GitHub.com.", dns=dns_ok("github.com"))["status"] == "OK"


def test_cname_mismatch_is_flagged():
    r = run("new-cdn.example.net", dns=dns_ok("www.microsoft.com-c-3.edgekey.net"))
    assert r["status"] == "WARNING"
    assert "CNAME mismatch" in r["issues"][0]["message"]


def test_expected_cname_but_no_cname_is_flagged():
    assert "no CNAME" in run("cdn.example.net", dns=dns_ok(None))["issues"][0]["message"]


def test_empty_expected_cname_means_no_comparison():
    assert run("", dns=dns_ok("anything.example"))["status"] == "OK"


def test_unresolvable_domain_is_critical_and_skips_other_checks():
    called = []
    r = check.evaluate("nope.example", "", dns_fail,
                       lambda d: called.append("ssl"), lambda d: called.append("http"))
    assert r["status"] == "CRITICAL" and called == []
    assert "Does not resolve" in r["issues"][0]["message"]


def test_invalid_ssl_is_critical():
    r = run(ssl_=ssl_bad("certificate has expired", -500))
    assert r["status"] == "CRITICAL" and "expired" in r["issues"][0]["message"]


def test_ssl_expiring_soon_is_warning():
    r = run(ssl_=ssl_ok(days=5))
    assert r["status"] == "WARNING" and "expires soon" in r["issues"][0]["message"]


def test_site_not_responding_is_critical():
    assert run(http_=http(None))["status"] == "CRITICAL"


def test_http_500_is_critical_but_403_counts_as_responding():
    assert run(http_=http(503))["status"] == "CRITICAL"
    assert run(http_=http(403))["status"] == "OK"   # bot protection, site is up


def test_new_issues_and_fixed_domains_are_detected():
    yesterday = [{"domain": "a.com", "status": "WARNING",
                  "issues": [{"severity": "WARNING", "message": "old problem"}]},
                 {"domain": "b.com", "status": "CRITICAL",
                  "issues": [{"severity": "CRITICAL", "message": "was broken"}]}]
    today = [{"domain": "a.com", "status": "CRITICAL",
              "issues": [{"severity": "WARNING", "message": "old problem"},
                         {"severity": "CRITICAL", "message": "new problem"}]},
             {"domain": "b.com", "status": "OK", "issues": []}]
    fixed = check.mark_new_issues(today, yesterday)
    assert [i["new"] for i in today[0]["issues"]] == [False, True]
    assert fixed == ["b.com"]


def test_retry_on_timeout_retries_once_then_succeeds():
    calls = []
    def flaky():
        calls.append(1)
        if len(calls) == 1:
            raise TimeoutError("slow server")
        return "ok"
    assert check.retry_on_timeout(flaky) == "ok" and len(calls) == 2


def test_retry_on_timeout_gives_up_after_second_timeout():
    calls = []
    def always_slow():
        calls.append(1)
        raise TimeoutError("slow server")
    with pytest.raises(TimeoutError):
        check.retry_on_timeout(always_slow)
    assert len(calls) == 2


def test_retry_does_not_retry_other_errors():
    calls = []
    def refused():
        calls.append(1)
        raise ConnectionRefusedError()
    with pytest.raises(ConnectionRefusedError):
        check.retry_on_timeout(refused)
    assert len(calls) == 1


def test_read_domains_skips_blank_rows(tmp_path):
    f = tmp_path / "d.csv"
    f.write_text("domain,expected_cname\na.com,\n\nb.com, x.net \n", encoding="utf-8")
    assert check.read_domains(f) == [("a.com", ""), ("b.com", "x.net")]


# ----------------------------------------------------------------------------- check_ssl() with real TLS

def _key():
    return ec.generate_private_key(ec.SECP256R1())


def _cert(subject_cn, key, issuer_cn, issuer_key, not_before, not_after, sans=(), ca=False):
    b = (x509.CertificateBuilder()
         .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject_cn)]))
         .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer_cn)]))
         .public_key(key.public_key()).serial_number(x509.random_serial_number())
         .not_valid_before(not_before).not_valid_after(not_after)
         .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
         # Python 3.13+ rejects certificates without these two identifiers
         .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
         .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_key.public_key()),
                        critical=False))
    if sans:
        b = b.add_extension(x509.SubjectAlternativeName([x509.DNSName(s) for s in sans]), critical=False)
    if ca:
        b = b.add_extension(x509.KeyUsage(digital_signature=True, key_cert_sign=True, crl_sign=True,
                                          content_commitment=False, key_encipherment=False,
                                          data_encipherment=False, key_agreement=False,
                                          encipher_only=False, decipher_only=False), critical=True)
    return b.sign(issuer_key, hashes.SHA256())


def _serve(tmp_path, name, cert, key):
    """Start a tiny TLS server on localhost that just completes handshakes. Returns its port."""
    cert_file, key_file = tmp_path / f"{name}.crt", tmp_path / f"{name}.key"
    cert_file.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_file.write_bytes(key.private_bytes(serialization.Encoding.PEM,
                                           serialization.PrivateFormat.PKCS8,
                                           serialization.NoEncryption()))
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert_file, key_file)
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen()

    def loop():
        while True:
            conn, _ = srv.accept()
            try:
                with ctx.wrap_socket(conn, server_side=True) as s:
                    s.recv(1)
            except (ssl.SSLError, OSError):
                pass

    threading.Thread(target=loop, daemon=True).start()
    return srv.getsockname()[1]


@pytest.fixture(scope="module")
def pki(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("pki")
    now = dt.datetime.now(dt.timezone.utc)
    ca_key = _key()
    ca = _cert("Test CA", ca_key, "Test CA", ca_key, now - dt.timedelta(days=1),
               now + dt.timedelta(days=3650), ca=True)
    ca_file = tmp / "ca.pem"
    ca_file.write_bytes(ca.public_bytes(serialization.Encoding.PEM))

    def leaf(name, sans, days_before, days_after, self_signed=False):
        k = _key()
        issuer_cn, issuer_key = (sans[0], k) if self_signed else ("Test CA", ca_key)
        c = _cert(sans[0], k, issuer_cn, issuer_key, now + dt.timedelta(days=days_before),
                  now + dt.timedelta(days=days_after), sans=sans)
        return _serve(tmp, name, c, k)

    return {
        "cafile": str(ca_file),
        "valid": leaf("valid", ["localhost"], -10, 60),
        "expired": leaf("expired", ["localhost"], -400, -30),
        "wrong_host": leaf("wrong", ["other.example"], -10, 60),
        "self_signed": leaf("self", ["localhost"], -10, 60, self_signed=True),
    }


def test_ssl_valid_cert_reports_days_left(pki):
    r = check.check_ssl("localhost", port=pki["valid"], cafile=pki["cafile"])
    assert r["valid"] and r["error"] is None and r["days_left"] in (59, 60)


def test_ssl_expired_cert(pki):
    r = check.check_ssl("localhost", port=pki["expired"], cafile=pki["cafile"])
    assert not r["valid"] and r["error"] == "certificate has expired"
    assert r["days_left"] in (-30, -31)  # expiry is still read from the bad certificate


def test_ssl_wrong_host(pki):
    r = check.check_ssl("localhost", port=pki["wrong_host"], cafile=pki["cafile"])
    assert not r["valid"] and r["error"] == "certificate does not match the domain name"


def test_ssl_self_signed(pki):
    r = check.check_ssl("localhost", port=pki["self_signed"], cafile=pki["cafile"])
    assert not r["valid"] and "self-signed" in r["error"]


def test_ssl_nothing_listening():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    r = check.check_ssl("localhost", port=port)
    assert not r["valid"] and "failed" in r["error"]
