# Aegis — evaluated local AI code review

A read-only code-review workspace combining 11 static rule families with optional local-model suggestions and evidence-constrained explanations. Aegis compares approaches instead of assuming that adding an LLM improves detection. **Static analysis remains the default because the recorded AI detector produced substantially more false positives.**

![Aegis evaluation dashboard](docs/aegis-evaluation.jpg)

## Run locally

Python 3.11+ (verified locally on 3.14). Start with `sh start.sh`, then open http://127.0.0.1:8090. First run installs pinned dependencies from PyPI into `.venv`. Set `PORT` for a different port. Optional Ollama defaults to http://127.0.0.1:11434; set `AEGIS_OLLAMA_URL` to another HTTP loopback endpoint. Install a completion model separately; Aegis never downloads one automatically.

Explore the built-in sample for five intentional review leads. Open a finding, inspect its source evidence/CWE/reference, record a decision, and export Markdown/JSON. Complete source files are not persisted. The sample and benchmark source strings must never be executed or deployed.

## What changed

- Scope-aware Python import/builtin shadowing, simple local alias and SQL-variable tracking, conservative branch merges and constant-query suppression.
- Length-preserving JavaScript comment/string/regex masking, multiline sink detection and common Node child_process aliases; still lexical heuristics, not a JS parser.
- Optional **Static + local AI** mode: schema-constrained, numbered source, exact full-line quote/rule validation, low-confidence AI origin labels, and per-file coverage/usage diagnostics. Union never removes static findings; busy/offline/invalid AI falls back to the static report.
- Structured explanations separate observed evidence, assumptions, verification steps and remediation. Invalid evidence/status/schema/external references are rejected. Matching quotes do not verify semantic truth.
- Frozen baseline, 96 synthetic labeled fixtures, dev/test separation, AI-only/static/union comparison, raw responses, failure analysis, source/model hashes and an explanation-contract suite.
- Evaluation screen displays recorded results and limitations. GitHub Actions verifies unit/API contracts, JS syntax, and static non-regression without downloading a model.

## Recorded evaluation

See [full protocol](evaluation/PROTOCOL.md), [test comparison](evaluation/results/test-qwen3-4b.md), [development comparisons](evaluation/results/dev-models.md), and [explanation contracts](evaluation/results/explanations-qwen3-4b.md). Full JSON/JSONL evidence is alongside these reports.

On 72 synthetic test cases (35 positive cases containing 36 expected leads, 36 negative cases, and one parse-abstention case):

| Approach | TP | FP | FN | Precision | Recall | F1 |
|---|---:|---:|---:|---:|---:|---:|
| Frozen original static | 28 | 19 | 8 | .5957 | .7778 | .6747 |
| Revised static | 36 | 0 | 0 | 1.0000 | 1.0000 | 1.0000 |
| Local Qwen3 4B only | 19 | 48 | 17 | .2836 | .5278 | .3689 |
| Static + local Qwen3 4B union | 36 | 48 | 0 | .4286 | 1.0000 | .6000 |

Invalid AI proposals count as false positives even when withheld from the product. These co-designed, public synthetic fixtures test specific rule patterns, not production exploit detection or independent generalization. No perfect-accuracy claim is justified. AI did not improve detection in this experiment; exposing that failure is part of the project.

A separate post-test [known-limit challenge](evaluation/results/challenge.md) deliberately probes eight unhandled language constructs. Revised static fails all eight (3 misses, 5 false positives), including two regressions versus baseline. These are retained, not repaired using challenge answers or mixed into the main score. This makes the limits of the perfect main-suite result explicit. No broad improvement or generalization claim is justified. Reproduce with `python -m evaluation.probe`.

95 automated regression/API/contract tests pass. The real Qwen3 4B explanation run passed 12/12 **structural** contracts; that is not independently measured factual correctness.

## Architecture and boundaries

FastAPI → bounded background workers → Python AST/JS lexical/static rules → optional loopback Ollama → evidence validation → SQLite reports → human triage/export. Vanilla browser UI. The model has no tools, code execution, file editing, network navigation or automatic fixes. Imported source is never installed or executed. No repository cloning or URL crawling.

Static limits: 100 files, 150,000 characters each, 2 MB source, 4 MB HTTP body. AI mode: 8 files, 12,000 characters each, 48,000 total. Two workers/four queued-or-running scans/one concurrent model request. No authentication: **single-user loopback only; never expose through a public tunnel**. Host/Origin/write-header boundaries and CSP reduce accidental cross-origin use; local programs/users may still access the service.

AI detection sends selected source after best-effort redaction to the configured local model. Explanations send only a redacted finding. Private-key bodies are masked while retaining line positions. Redaction is not guaranteed: do not submit unauthorized source. Findings, redacted excerpts, model text, names and notes persist under data/aegis.db; complete uploads are not saved. Review exports before sharing.

A finding is a review lead, not a proven exploit. Severity/confidence describe the pattern match, not deployment impact. Python handling is bounded and lacks complete control-flow, cross-file taint/call graphs and runtime semantics. JS has lexical blind spots, including template interpolation and incomplete shadowing. There is no dependency advisory lookup, live attack testing, verified remediation or exhaustive language coverage. Clean scans do not prove security. AI interpretations can be wrong despite exact quotations; human review remains necessary.

## Verification and honest project description

```sh
.venv/bin/python -m pytest -q
node --check static/app.js
.venv/bin/python -m evaluation.run --split test --output /tmp/aegis-static
.venv/bin/python -m evaluation.gate /tmp/aegis-static.json
```

Implementation and fixtures were developed with AI assistance. Describe the work as an evaluated prototype with transparent limitations; do not claim independent security research, production adoption, real incidents prevented or personally authored work that you have not reviewed and can explain. The evaluation is diagnostic evidence, not a certification.

Aegis is independent of Orbit and Relay. Neither is required to run it.
