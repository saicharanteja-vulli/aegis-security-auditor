# Aegis — Autonomous AI Security Auditor

A standalone, local security-review workspace. Upload source, let a background worker inspect it, review evidence, ask a local Ollama model for context, and export a sourced report. Aegis uses an ivory / blue editorial interface inspired by Orbit and Relay, with its own animated radar identity.

![Aegis security review dashboard](docs/aegis-dashboard.png)

## Run

Requires Python 3.11+ (tested on 3.14).

```sh
git clone https://github.com/saicharanteja-vulli/aegis-security-auditor.git
cd aegis-security-auditor
sh start.sh
```

Open http://127.0.0.1:8090. First run installs the pinned Python dependencies from PyPI. Set `PORT` to use another port. The `.venv` is created locally and is excluded from the repository.

## Try it

1. Click **Explore a sample** to inspect three intentionally vulnerable example files.
2. The scan finds five review leads: interpolated SQL, shell execution, unsafe deserialization, disabled TLS verification, and an HTML injection sink.
3. Open a finding to see its file, line, evidence, confidence, remediation and reference.
4. Optionally start Ollama, choose an installed model in **Local intelligence**, and click **Explain with local AI**. This sends only that finding's redacted evidence to `127.0.0.1:11434`. No cloud model is used and no model is downloaded automatically.
5. Save a review state and note, then export Markdown or JSON.
6. Use **Start a review** for your own files or folder. Only scan code you own or are authorized to inspect.

The sample is deliberately unsafe and must never be deployed. File `examples/review_fixture.py` is another upload fixture; it is not an executable example.

## Features and architecture

- FastAPI server, SQLite report storage, bounded background thread pool, vanilla JS/CSS.
- 11 static rules: Python AST analysis, JavaScript/TypeScript heuristics, credential and private-key markers.
- Automatic inspect → collect → prioritize → report pipeline. AI explanations are explicitly requested, not autonomous exploitation or remediation.
- Live scan progress, coverage warnings, search, priority/state filters, review notes and persistent scan history.
- CWE identifiers and links to OWASP, Python, MDN and Node guidance.
- Local Ollama model discovery; explanation failures do not invalidate static reports.
- 100 files per scan, 150,000 characters per file (browser limits files to 150 KB), 2 MB source total, 4 MB HTTP body. Two scan workers, four queued/running jobs, one concurrent AI request.
- No repository clone, URL crawl, shell execution, package installation from uploaded projects, or automatic file changes.

## Boundaries and limitations

**This is a local single-user MVP, not a production security audit service.** It binds to loopback, restricts Host and Origin, requires a custom header for writes, and uses a strict content-security policy. There is no account system. Do not put it behind a public tunnel or proxy. Other programs/users with access to this Mac can potentially access its local API and data.

Findings identify patterns, not proven exploitable vulnerabilities. Severity reflects the pattern, not a complete assessment of application impact. Confidence describes the match. There is no whole-program taint tracking, dependency advisory database, live-system penetration testing, cross-file call graph or exhaustive JavaScript parser. Python alias resolution is basic and does not model shadowing. Dynamic SQL stored in an earlier variable can be missed. Comments and strings can cause text-check false positives. Review or dismissal is a human label, not verification of a code fix.

Uploaded complete source is not saved to disk. Names, findings, evidence, notes and explanations are retained under `data/aegis.db`. Redaction is best effort and does not guarantee removal of every secret. Do not upload code you are not permitted to inspect. Review exported reports before sharing. AI explanations may contain errors and cannot run tools or edit source. A clean scan is not proof of security.

Only the latest 100 scans are listed in the UI. Reports remain in the database. Scan history is local to this installation. Restarting the app marks interrupted scans failed instead of claiming completion.

## Tests

```sh
.venv/bin/python -m pytest -q
```

43 automated tests cover risky and safer Python examples, JS checks, redaction, malformed syntax, path rejection, read-only behavior, background scan completion, reports, triage persistence, request boundaries, and AI success/failure handling. Real Ollama and browser checks are separate from unit tests.

## Source guidance

- SQL injection: https://community.owasp.org/attacks/SQL_Injection
- Command injection: https://community.owasp.org/attacks/Command_Injection
- Unsafe deserialization: https://docs.python.org/3/library/pickle.html

Aegis is independent of Orbit and Relay. Neither app needs to be running.
