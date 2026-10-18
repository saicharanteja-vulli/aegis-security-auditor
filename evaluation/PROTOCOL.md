# Aegis evaluation protocol

## Scope and provenance

96 original, hand-authored synthetic source snippets: 24 development, 72 test. The first risky/safer pair in each of 11 rule families goes to development; remaining variants and six boundary cases form the test split. Explicit labels in `create_fixtures.py` describe rule-and-line **review leads**, not verified vulnerabilities. Source strings are parsed/read, never executed. Test variants share rule families with development. The code and corpus were co-designed with AI assistance, with no independent human adjudication. Perfect static results therefore demonstrate regression coverage, not independent generalization or production accuracy.

The frozen baseline is the unmodified `aegis/scanner.py` from commit `0e866b2c8f63a0e60bf120dc7633a50736593152`, copied to `baseline/scanner.py` before analyzer changes. SHA-256: `aa4213e7cb9ac4d995fe6edf08504748e54ac31dac57012e0be7ddc9779d7ec2`. Both versions receive identical paths and sources.

## Experiment sequence

1. Create labels and split before model evaluation. Compare baseline/current on development.
2. Run development comparisons with installed Qwen3 1.7B and 4B. The 1.7B model returned inconsistent reviewable/findings envelopes in 21/24 cases. Select 4B for the larger test because it returned valid envelopes on all development cases; it still had poor detection precision/recall. No claim of a universal model ranking.
3. Freeze detection prompt, schema, generation settings, corpus, and analyzers for the 72-case run. Do not repair failures using test answers. No test-driven prompt or detector changes were made afterward. Later work adds UI, tests, reporting and model-discovery validation.
4. Run explanation-contract evaluation on the first current-static finding per available test family, selected in fixed dataset order. This is a separate structural check, not semantic accuracy.

`dev-models.json` is the initial development run. Its 21 invalid-envelope 1.7B failures retain error messages but lost raw responses in the original runner. This logging limitation is explicit. The runner was corrected to preserve raw responses and usage on validation failures before the test run. A separately labeled development recapture may be included; it is not substituted for the initial result.

## Scoring

A TP matches the hand-authored rule **and exact line**. A wrong line causes an FP and leaves an FN. Accepted duplicate identities are deduplicated and recorded. Unknown rules, wrong lines, fabricated quotes and invalid item schemas are withheld from the product but each rejected proposal counts as a benchmark FP. Malformed response envelopes are errors, not clean reviews; positive labels remain missed. Model declines on valid negative cases remain unreviewed in specificity's denominator. An explicit parse-abstention case passes only when declined. Empty predictions do not imply security.

Precision = TP/(TP+FP); recall = TP/(TP+FN); F1 = 2TP/(2TP+FP+FN). Zero-denominator precision/recall are null. Negative-case false-positive rate is cases with any false proposal divided by all labeled negative cases. Specificity is successfully reviewed negatives without proposals divided by all negative cases; unreviewed cases are not silently excluded. Hybrid retains static findings and unions accepted AI identities; AI-stage errors/declines are still reflected in exact-case coverage. Hybrid and AI share the same response, avoiding a second sampled comparison.

The conservative benchmark FP total includes rejected proposals; the UI shows only accepted leads. Read per-case diagnostics to distinguish them. A line-matching quote establishes provenance, not entailment. Prompt-injection examples are a small diagnostic subset, not an attack-resistance certification.

## Artifacts and reproducibility

`results/*.json` includes labels, source, predictions, misses, false positives, raw model objects, diagnostics, settings, prompt/schema, dataset/source hashes, model digests, environment, and timings. JSONL journals flush after each case; Markdown summarizes failures. Raw synthetically generated credential examples contain no real secrets. Model tags can drift: compare recorded digests. Token counts and single-machine timings are observations with caching/load effects, not universal speed/cost guarantees. Dependencies are pinned in requirements.txt; no model is downloaded by the suite.

```sh
python -m pytest -q
python -m evaluation.run --split test --output /tmp/aegis-static
python -m evaluation.gate /tmp/aegis-static.json
AEGIS_OLLAMA_URL=http://127.0.0.1:11434 python -m evaluation.run --split test --models qwen3:4b --output /tmp/aegis-model
AEGIS_OLLAMA_URL=http://127.0.0.1:11434 python -m evaluation.explain --model qwen3:4b --output /tmp/aegis-explain
```

The static gate rejects increases in FP/FN or lower exact-case pass rate against the frozen baseline. It does not gate probabilistic local-model quality or declare a security audit successful. Model-run errors produce a nonzero exit but detection-quality misses remain reported. CI runs static comparisons and contract/regression tests; it does not download/run LLMs.

## Remaining blind spots

Python tracking is bounded local syntax, not full control-flow or taint analysis. It does not fully model try/while/comprehension/nonlocal/global semantics, runtime monkey patching, interprocedural calls or cross-file wrappers. A nonconstant SQL expression may be safe after validation; a constant query can still have other flaws. JS uses lexical masking/regex rather than a parser; aliases, shadowing, template interpolation, unusual regex and TypeScript syntax can escape coverage. Secret recognition/redaction uses patterns and is best effort. Parser failure produces coverage warnings rather than invented findings. No dependency CVEs, runtime exploitation, validated fixes or security certification.

## Post-test known-limit challenge

Eight hand-authored diagnostic probes were added after the main run to expose documented limitations rather than conceal them behind the main score. Run `python -m evaluation.probe`. Revised static has 0 TP, 5 FP and 3 FN (0/8 exact-case passes); baseline has 2 TP, 5 FP and 1 FN. Masking template interpolation and the default Node import are regressions relative to the original broad text checks. Optional eval calls, lambda/comprehension shadowing, unrelated methods, regex after return and namespace reassignment remain blind spots. These cases were not used to tune the analyzer, and they are not hidden/independent samples. Future repairs must create a new version and preserve this recorded result.
