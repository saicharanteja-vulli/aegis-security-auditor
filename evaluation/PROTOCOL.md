# Aegis evaluation protocol

## Version history and honest interpretation

The original v1 run is preserved in `results/test-qwen3-4b.*`, `results/challenge.*`, and the other original result files. `results/v1/` retains its dashboard summary, challenge report and protocol. v1's revised analyzer passed the 72-case main suite but failed all eight targeted edge cases, including two regressions relative to the frozen original scanner.

v2 repairs those eight known cases. The JavaScript/TypeScript path now parses syntax trees using pinned Tree-sitter grammars instead of regex/lexical masking. Python lambda parameters and comprehension targets get bounded scope handling, including the enclosing function's local-name collector. No benchmark source is executed.

**The repaired cases informed implementation.** They are regression/development examples, not a hidden holdout or independent accuracy evidence. Sources, paths and expected labels are unchanged; an automated test compares them against the preserved v1 failure report. Their metadata/rationales identify the original failure mechanisms. The original 96-case main dataset is unchanged. Its public, co-designed dev/test variants share rule families, so it also does not establish independent generalization.

`results/v2/initial-comparison.*` retains the first rerun before a final enclosing-function scope adjustment. `results/v2/test-qwen3-4b.*` is the complete final rerun after analyzer changes stopped. Neither is substituted for the v1 result. The final source hashes identify the analyzer and model-client implementations used. The git_revision field records HEAD at launch and can precede uncommitted working changes; source hashes, rather than that parent revision alone, identify the evaluated files. UI/reporting edits do not change detection labels or the model prompt.

## Data and baseline

96 original synthetic snippets: 24 development, 72 test. First positive/negative variant in each of 11 rule families goes to development; remaining variants and six boundary examples go to test. The test split contains 35 positive cases with 36 expected leads, 36 negatives, and one expected parse-abstention case. Eight additional previously failing examples are a separate repaired-case regression set.

Explicit rule/line labels are hand-authored in `create_fixtures.py` and `challenge.json`, never inferred from model/scanner output. They describe local review leads, not proven vulnerabilities. No uploaded project, secret, incident or customer data is included. Fixtures and implementation were developed with AI assistance, without independent human adjudication.

`baseline/scanner.py` is an unchanged copy of the original `aegis/scanner.py` at commit `0e866b2c8f63a0e60bf120dc7633a50736593152`. It is frozen, receives identical source/path inputs, and is never repaired alongside the current analyzer. Its hash is present in full evaluation reports. v1 implementation is recoverable at `32ebec57c500e96cba2ff005a1c52b6e4f115b11` in Git history.

## Scoring and error handling

A TP matches both expected rule and exact source line. Wrong-line predictions are FPs and leave the expected label missed. Valid duplicate identities are deduplicated and recorded. Unknown rules, wrong lines, fabricated quotes and invalid item schemas are withheld from the product; each rejected proposal nevertheless counts as a benchmark FP. Malformed envelopes/provider failures count as errors, never successful clean reviews. Positive labels remain missed. Declines/errors on valid negative cases remain in specificity's denominator as unreviewed, rather than being silently excluded. Expected parse-abstention cases pass only when declined.

Precision = TP/(TP+FP); recall = TP/(TP+FN); F1 = 2TP/(2TP+FP+FN). A zero-denominator precision/recall is null. Negative-case FP rate is the number of negative cases with any false proposal divided by all negative cases. Specificity is successfully reviewed negatives without proposals divided by all negatives. Empty findings do not imply security.

AI and hybrid use the same model response per case. Hybrid unions accepted AI identities with all static findings, never removes a static finding, and retains AI-stage errors/declines in exact-case coverage. Its benchmark FP total includes rejected proposals even though the UI withholds them. See per-case diagnostics before interpreting the aggregate.

## Model protocol

The original development run compared Qwen3 1.7B and 4B with identical detection settings. 1.7B produced 21/24 inconsistent envelopes; 4B had valid envelopes but poor precision/recall, so 4B was selected for test comparison. No universal model ranking is claimed. The initial 1.7B failures lost raw responses in the original runner; that limitation is explicit, and `dev-1.7b-recapture.*` preserves a separately labeled repeat with corrected logging.

v2 reruns the installed Qwen3 4B model on all 72 main test cases after analyzer repairs. Detection prompt/schema, redaction, generation settings and model-client validation remain unchanged. Reports record model digests, prompt/schema, source and dataset hashes, pinned grammar/runtime package versions, temperature 0, seed 42, context 8192, output limit 1100, and thinking disabled. No model is downloaded by the runner. Repeated seeded requests on one local machine are not population estimates; timing/token counts are observations affected by caching, load and runtime differences.

Explanation evaluation selects the first current-static finding per available test family in fixed dataset order. It uses the app's prompt, schema and validator, retains raw responses and model/source metadata, and checks exact evidence/status/schema, bounded assumptions/verification steps, and absence of generated URLs. This measures the structural contract, **not semantic truth, exploitability, prompt-injection immunity, or working remediation**. No independent semantic grading is claimed.

## Reproduce

Install pinned requirements, then from the repository root:

```sh
python -m pytest -q
node --check static/app.js
python -m evaluation.run --split dev --output /tmp/aegis-dev
python -m evaluation.run --split test --output /tmp/aegis-static
python -m evaluation.gate /tmp/aegis-static.json
python -m evaluation.probe --output /tmp/aegis-repaired
AEGIS_OLLAMA_URL=http://127.0.0.1:11434 python -m evaluation.run --split test --models qwen3:4b --output /tmp/aegis-model
AEGIS_OLLAMA_URL=http://127.0.0.1:11434 python -m evaluation.explain --model qwen3:4b --output /tmp/aegis-explanations
```

JSONL journals flush each case; final JSON retains source, labels, raw responses, diagnostics, misses/false positives and metadata. Markdown summarizes failures. Model/provider errors cause a nonzero exit, while quality misses remain visible in reports. The repaired-case runner exits nonzero if any of its eight current-static cases fails. The static gate rejects higher FP/FN or lower exact-case pass rate against the frozen baseline on the main suite. CI runs tests, syntax, static comparison/gate and repaired cases; it does not download or run an LLM.

## Remaining limits

Syntax parsing improves separation of executable expressions from inert text, but it does not resolve types, evaluate JavaScript, or prove provenance/reachability. JS alias tracking is bounded/sequential; complete hoisting, closure capture, loops, try/catch, destructuring defaults, computed/dynamic properties, re-exports and cross-file flows are not fully modeled. Arbitrary custom methods and aliases may be missed. HTML review covers inline script blocks only; event handlers and external scripts are outside scope. A parse error yields a coverage warning and only secret/key text checks, not a clean syntactic review.

Python handling still lacks full CFG/taint analysis, try/while/global/nonlocal/walrus/closure semantics, runtime monkey patching and interprocedural resolution. Comprehension targets and lambda argument lists are handled for the tested patterns, not every Python scope behavior. Secret recognition/redaction is pattern-based and best effort. No dependency advisory lookup, runtime exploitation, validated fixes or security certification is provided. Human triage labels do not prove a fix.
