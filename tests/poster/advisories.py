"""A fake of the two advisory endpoints for poster tests (ai-tools-alerts#3qyq): the
JSON ``api.github.com/advisories/<id>`` and ``api.osv.dev/v1/vulns/<id>`` answer with,
and a fetch of ``verify.default_fetch``'s shape that serves it."""

import json

GH, OSV = "https://api.github.com/advisories/", "https://api.osv.dev/v1/vulns/"
NPM = ("npm", "@anthropic-ai/claude-code", "< 2.1.0", "2.1.0")


def ghsa_json(ghsa_id, *, type="reviewed", cwes=("CWE-78",), packages=(NPM,), repo="anthropics/claude-code",
              cve=None, withdrawn_at=None, identifiers=(), severity="high",
              vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H"):
    """The unauthenticated answer for one global advisory, with the keys the reading uses."""
    return {"ghsa_id": ghsa_id, "cve_id": cve, "type": type, "severity": severity, "withdrawn_at": withdrawn_at,
            "repository_advisory_url": None if repo is None else
            f"https://api.github.com/repos/{repo}/security-advisories/{ghsa_id}",
            "identifiers": [{"type": "GHSA", "value": ghsa_id}, *({"type": "CVE", "value": cve},) * bool(cve),
                            *({"type": "OTHER", "value": i} for i in identifiers)],
            "cvss_severities": {"cvss_v3": {"vector_string": vector, "score": 8.8},
                                "cvss_v4": {"vector_string": None, "score": 0.0}},
            "cwes": [{"cwe_id": c, "name": "a weakness"} for c in cwes],
            "vulnerabilities": [{"package": {"ecosystem": e, "name": n}, "vulnerable_version_range": a,
                                 "first_patched_version": p, "vulnerable_functions": []} for e, n, a, p in packages]}


def osv_json(osv_id, *, packages=(("npm", "@anthropic-ai/claude-code"),), withdrawn=None, aliases=()):
    return {"id": osv_id, "aliases": list(aliases), **({"withdrawn": withdrawn} if withdrawn else {}),
            "affected": [{"package": {"ecosystem": e, "name": n}} for e, n in packages]}


class Api:
    """``put(id, x)``: x a dict (a 200 with that JSON), bytes (a 200 with that body), an
    int (that status), or an exception to raise. An id never put answers ``default(id)``
    when a default is given, else 404."""

    def __init__(self, default=None, **answers):
        self.answers, self.calls, self.timeouts, self.default = {}, [], [], default
        for k, v in answers.items():
            self.put(k, v)

    def put(self, lookup_id, answer):
        self.answers[lookup_id] = answer

    def __call__(self, url, etag, limit, timeout):
        self.calls.append(url)
        self.timeouts.append(timeout)
        assert etag is None and url.startswith((GH, OSV)), url
        i = url.rsplit("/", 1)[1]
        a = self.answers[i] if i in self.answers else self.default(i) if self.default else 404
        if isinstance(a, BaseException):
            raise a
        if isinstance(a, int):
            return a, None, b""
        return 200, None, a if isinstance(a, bytes) else json.dumps(a).encode()


def plain(i):
    """The answer of an API that works and adds nothing to what the vendor's page says:
    a reviewed advisory of the vendor's own with no weakness listed, which the ruleset
    rates a notice. The default of the poster tests' ``env``."""
    return ghsa_json(i, cwes=()) if i.startswith("GHSA-") else 404
