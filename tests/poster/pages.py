"""Vendor pages for poster tests: the markup ``rules.read_advisory`` reads, rendered for
any values, and a fake fetch that serves them (ai-tools-alerts#h340)."""

import html
import json
import re

from aitools_alerts import schema

REPO_URL = re.compile(r"https://github\.com/([^/]+/[^/]+)/security/advisories/(GHSA(?:-[0-9a-z]{4}){3})")


def advisory_page(ghsa, package="@anthropic-ai/claude-code", ecosystem="npm", affected="< 2.1.0",
                  patched="2.1.0", cve=None, severity="High", title="A flaw", repo="anthropics/claude-code",
                  description="Details.", blocks=None):
    """A repository security advisory page in GitHub's shape. ``ecosystem`` None renders
    the "Software" label; ``blocks`` (name, ecosystem, affected, patched) replaces the one block."""
    out = [f"<html><head><title>{html.escape(title)} · Advisory · {repo} · GitHub</title></head><body>",
           f"<h1>{html.escape(title)}</h1><span>{severity}</span><span>published</span>",
           f"<div>{ghsa}</div><relative-time>Nov 5, 2026</relative-time>"]
    for name, eco, aff, fix in blocks or [(package, ecosystem, affected, patched)]:
        label = "Software" if eco is None else "Package"
        registry = "" if eco is None else f"<span>(<a>{eco}</a>)</span>"
        out.append(f'<h2>{label}</h2><span>{html.escape(name)}</span>{registry}'
                   f'<h2>Affected versions</h2><div>{html.escape(aff or "")}</div>'
                   f'<h2>Patched versions</h2><div>{html.escape(fix or "None")}</div>')
    out += [f'<h2>Description</h2><div><p>{html.escape(description)}</p></div>',
            f"<h3>Severity</h3><span>{severity}</span>",
            f'<h3 data-view-component="true" class="mb-2 f6">CVE ID</h3> <div class="color-fg-muted"> '
            f'{cve or "No known CVE"} </div><h3>Weaknesses</h3></body></html>']
    return "\n".join(out)


_CVE = re.compile(r"CVE-\d{4}-\d{4,}", re.I)
_SEVERE = re.compile(r"execution|credential|data loss|high|critical", re.I)
_CONSEQUENCE = re.compile(r"execution|credential|data loss", re.I)  # what a vendor's title would say (9kgk)
_NAMES = " ".join(sorted({n for e in schema.load_scope() for n in [e.name, *(c.name for c in e.components)]}))


class Pages:
    """A fake ``rules.http_page``. A URL set with ``put`` answers that; any other
    repository advisory URL answers the page of the finding (``add``) that cites it,
    whose product, fixed version, range, title and severity the page then states; any other
    URL answers a plain page naming every finding's ids and every product."""

    def __init__(self):
        self.fixed, self.findings, self.calls = {}, [], []

    def put(self, url, text, status=200):
        self.fixed[url] = (status, text)

    def add(self, findings):
        self.findings += [f for f in findings if isinstance(f, dict)]

    def __call__(self, url, allow=None, timeout=None):
        self.calls.append(url)
        if url in self.fixed:
            return self.fixed[url]
        m = REPO_URL.fullmatch(url)
        if not m:
            return 200, f"<html><title>Security</title>{html.escape(json.dumps(self.findings))} {_NAMES}</html>"
        f = next((f for f in reversed(self.findings)
                  if any(isinstance(s, dict) and s.get("url") == url for s in f.get("sources") or [])), {})
        ids = [i for i in [f.get("id"), *(f.get("aliases") or [])] if isinstance(i, str)]
        sev = f.get("advisory_severity")
        title = next((s["title"] for s in f.get("sources") or [] if s.get("url") == url and s.get("title")), "")
        if not title and isinstance(sev, str) and _CONSEQUENCE.search(sev):
            title = sev  # 9kgk: the page's title names the consequence; the severity word alone sets nothing
        pkg = f.get("package")
        name, eco = (pkg["name"], pkg["ecosystem"]) if isinstance(pkg, dict) else (f.get("product") or "", None)
        return 200, advisory_page(
            m.group(2), package=name, ecosystem=eco, affected=f.get("affected"), patched=f.get("fixed"),
            cve=next((_CVE.match(i).group().upper() for i in ids if _CVE.match(i)), None),
            severity="High" if isinstance(sev, str) and _SEVERE.search(sev) else "Low",
            title=title, repo=m.group(1))
