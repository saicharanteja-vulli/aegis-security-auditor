# Aegis review-lead evaluation

Split: test | Dataset: aegis-review-v1 | Run: 2026-10-18T05:21:36.037825+00:00

Original synthetic fixtures with hand-authored rule/line review labels. This is not a production vulnerability-detection accuracy claim.

| Strategy | Cases | TP | FP | FN | Precision | Recall | F1 | Errors |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| baseline | 72 | 28 | 19 | 8 | 0.5957 | 0.7778 | 0.6747 | 0 |
| static | 72 | 36 | 0 | 0 | 1.0 | 1.0 | 1.0 | 0 |
| ai:qwen3:4b | 72 | 19 | 48 | 17 | 0.2836 | 0.5278 | 0.3689 | 0 |
| hybrid:qwen3:4b | 72 | 36 | 48 | 0 | 0.4286 | 1.0 | 0.6 | 0 |

## What is measured

- A true positive matches the expected rule AND exact source line. Wrong-line predictions count as false positives and leave a missed expected finding.
- Invalid AI proposals count as false positives in the benchmark, even though the application withholds them. Duplicate valid identities are deduplicated and recorded.
- Model errors leave positive findings missed and are never counted as successful clean reviews. Unreviewed negative cases remain in the specificity denominator.
- Hybrid is the union of current static findings and source-validated AI leads. It never removes a static finding. AI and hybrid use the same model response per case.
- Labels describe local review patterns, not proven exploitability. All fixtures are synthetic and public; dev/test variants share rule families. The benchmark was co-designed with the implementation, so it is not independent generalization evidence.
- Precision/recall do not measure explanation entailment or whether a suggested fix works. The full source, labels, accepted findings, rejected proposals, raw model responses and usage are retained in JSON.
- Timing is one development-machine sample with cache/load effects and other verification activity; do not infer a universal model or performance ranking.

## Misses and false positives

- baseline / py001-negative-2: TP=0, FP=1, FN=0, declined=False, error=None
- baseline / py001-negative-3: TP=0, FP=1, FN=0, declined=False, error=None
- baseline / py002-positive-4: TP=0, FP=0, FN=1, declined=False, error=None
- baseline / py002-negative-2: TP=0, FP=1, FN=0, declined=False, error=None
- baseline / py002-negative-3: TP=0, FP=1, FN=0, declined=False, error=None
- baseline / py003-positive-2: TP=0, FP=0, FN=1, declined=False, error=None
- baseline / py003-positive-3: TP=0, FP=0, FN=1, declined=False, error=None
- baseline / py003-negative-3: TP=0, FP=1, FN=0, declined=False, error=None
- baseline / py004-positive-4: TP=0, FP=0, FN=1, declined=False, error=None
- baseline / py004-negative-2: TP=0, FP=1, FN=0, declined=False, error=None
- baseline / py004-negative-3: TP=0, FP=1, FN=0, declined=False, error=None
- baseline / py005-negative-3: TP=0, FP=1, FN=0, declined=False, error=None
- baseline / py006-negative-3: TP=0, FP=1, FN=0, declined=False, error=None
- baseline / js001-positive-4: TP=0, FP=0, FN=1, declined=False, error=None
- baseline / js001-negative-2: TP=0, FP=1, FN=0, declined=False, error=None
- baseline / js001-negative-3: TP=0, FP=1, FN=0, declined=False, error=None
- baseline / js002-positive-4: TP=0, FP=0, FN=1, declined=False, error=None
- baseline / js002-negative-2: TP=0, FP=1, FN=0, declined=False, error=None
- baseline / js002-negative-3: TP=0, FP=1, FN=0, declined=False, error=None
- baseline / js002-negative-4: TP=0, FP=1, FN=0, declined=False, error=None
- baseline / js003-positive-2: TP=0, FP=0, FN=1, declined=False, error=None
- baseline / js003-positive-3: TP=0, FP=0, FN=1, declined=False, error=None
- baseline / js003-negative-3: TP=0, FP=1, FN=0, declined=False, error=None
- baseline / js003-negative-4: TP=0, FP=1, FN=0, declined=False, error=None
- baseline / test-comments: TP=0, FP=3, FN=0, declined=False, error=None
- ai:qwen3:4b / py001-negative-2: TP=0, FP=1, FN=0, declined=False, error=None
- hybrid:qwen3:4b / py001-negative-2: TP=0, FP=1, FN=0, declined=False, error=None
- ai:qwen3:4b / py001-negative-3: TP=0, FP=1, FN=0, declined=False, error=None
- hybrid:qwen3:4b / py001-negative-3: TP=0, FP=1, FN=0, declined=False, error=None
- ai:qwen3:4b / py002-positive-2: TP=0, FP=0, FN=1, declined=False, error=None
- ai:qwen3:4b / py002-positive-4: TP=1, FP=1, FN=0, declined=False, error=None
- hybrid:qwen3:4b / py002-positive-4: TP=1, FP=1, FN=0, declined=False, error=None
- ai:qwen3:4b / py002-negative-2: TP=0, FP=1, FN=0, declined=False, error=None
- hybrid:qwen3:4b / py002-negative-2: TP=0, FP=1, FN=0, declined=False, error=None
- ai:qwen3:4b / py002-negative-3: TP=0, FP=1, FN=0, declined=False, error=None
- hybrid:qwen3:4b / py002-negative-3: TP=0, FP=1, FN=0, declined=False, error=None
- ai:qwen3:4b / py002-negative-4: TP=0, FP=1, FN=0, declined=False, error=None
- hybrid:qwen3:4b / py002-negative-4: TP=0, FP=1, FN=0, declined=False, error=None
- ai:qwen3:4b / py003-positive-2: TP=0, FP=1, FN=1, declined=False, error=None
- hybrid:qwen3:4b / py003-positive-2: TP=1, FP=1, FN=0, declined=False, error=None
- ai:qwen3:4b / py003-positive-3: TP=0, FP=1, FN=1, declined=False, error=None
- hybrid:qwen3:4b / py003-positive-3: TP=1, FP=1, FN=0, declined=False, error=None
- ai:qwen3:4b / py003-negative-2: TP=0, FP=1, FN=0, declined=False, error=None
- hybrid:qwen3:4b / py003-negative-2: TP=0, FP=1, FN=0, declined=False, error=None
- ai:qwen3:4b / py004-positive-2: TP=0, FP=0, FN=1, declined=False, error=None
- ai:qwen3:4b / py004-positive-3: TP=0, FP=0, FN=1, declined=False, error=None
- ai:qwen3:4b / py004-negative-2: TP=0, FP=1, FN=0, declined=False, error=None
- hybrid:qwen3:4b / py004-negative-2: TP=0, FP=1, FN=0, declined=False, error=None
- ai:qwen3:4b / py004-negative-3: TP=0, FP=1, FN=0, declined=False, error=None
- hybrid:qwen3:4b / py004-negative-3: TP=0, FP=1, FN=0, declined=False, error=None
- ai:qwen3:4b / py004-negative-4: TP=0, FP=1, FN=0, declined=False, error=None
- hybrid:qwen3:4b / py004-negative-4: TP=0, FP=1, FN=0, declined=False, error=None
- ai:qwen3:4b / py005-positive-2: TP=0, FP=0, FN=1, declined=False, error=None
- ai:qwen3:4b / py005-positive-4: TP=0, FP=0, FN=1, declined=False, error=None
- ai:qwen3:4b / py005-negative-3: TP=0, FP=1, FN=0, declined=False, error=None
- hybrid:qwen3:4b / py005-negative-3: TP=0, FP=1, FN=0, declined=False, error=None
- ai:qwen3:4b / py006-positive-4: TP=0, FP=0, FN=1, declined=False, error=None
- ai:qwen3:4b / py006-negative-3: TP=0, FP=1, FN=0, declined=False, error=None
- hybrid:qwen3:4b / py006-negative-3: TP=0, FP=1, FN=0, declined=False, error=None
- ai:qwen3:4b / sec001-positive-2: TP=0, FP=0, FN=1, declined=False, error=None
- ai:qwen3:4b / sec001-positive-3: TP=0, FP=0, FN=1, declined=True, error=None
- hybrid:qwen3:4b / sec001-positive-3: TP=1, FP=0, FN=0, declined=True, error=None
- ai:qwen3:4b / sec001-positive-4: TP=0, FP=0, FN=1, declined=False, error=None
- ai:qwen3:4b / js001-positive-2: TP=0, FP=0, FN=1, declined=False, error=None
- ai:qwen3:4b / js001-negative-2: TP=0, FP=1, FN=0, declined=False, error=None
- hybrid:qwen3:4b / js001-negative-2: TP=0, FP=1, FN=0, declined=False, error=None
- ai:qwen3:4b / js001-negative-4: TP=0, FP=2, FN=0, declined=False, error=None
- hybrid:qwen3:4b / js001-negative-4: TP=0, FP=2, FN=0, declined=False, error=None
- ai:qwen3:4b / js002-positive-3: TP=0, FP=1, FN=1, declined=False, error=None
- hybrid:qwen3:4b / js002-positive-3: TP=1, FP=1, FN=0, declined=False, error=None
- ai:qwen3:4b / js002-positive-4: TP=0, FP=1, FN=1, declined=False, error=None
- hybrid:qwen3:4b / js002-positive-4: TP=1, FP=1, FN=0, declined=False, error=None
- ai:qwen3:4b / js002-negative-2: TP=0, FP=1, FN=0, declined=False, error=None
- hybrid:qwen3:4b / js002-negative-2: TP=0, FP=1, FN=0, declined=False, error=None
- ai:qwen3:4b / js002-negative-4: TP=0, FP=1, FN=0, declined=False, error=None
- hybrid:qwen3:4b / js002-negative-4: TP=0, FP=1, FN=0, declined=False, error=None
- ai:qwen3:4b / js003-negative-2: TP=0, FP=1, FN=0, declined=False, error=None
- hybrid:qwen3:4b / js003-negative-2: TP=0, FP=1, FN=0, declined=False, error=None
- ai:qwen3:4b / cfg001-positive-2: TP=0, FP=0, FN=1, declined=True, error=None
- hybrid:qwen3:4b / cfg001-positive-2: TP=1, FP=0, FN=0, declined=True, error=None
- ai:qwen3:4b / cfg001-positive-3: TP=0, FP=1, FN=1, declined=False, error=None
- hybrid:qwen3:4b / cfg001-positive-3: TP=1, FP=1, FN=0, declined=False, error=None
- ai:qwen3:4b / cfg001-positive-4: TP=0, FP=1, FN=1, declined=False, error=None
- hybrid:qwen3:4b / cfg001-positive-4: TP=1, FP=1, FN=0, declined=False, error=None
- ai:qwen3:4b / cfg001-negative-2: TP=0, FP=1, FN=0, declined=False, error=None
- hybrid:qwen3:4b / cfg001-negative-2: TP=0, FP=1, FN=0, declined=False, error=None
- ai:qwen3:4b / cfg001-negative-3: TP=0, FP=0, FN=0, declined=True, error=None
- hybrid:qwen3:4b / cfg001-negative-3: TP=0, FP=0, FN=0, declined=True, error=None
- ai:qwen3:4b / cfg001-negative-4: TP=0, FP=0, FN=0, declined=True, error=None
- hybrid:qwen3:4b / cfg001-negative-4: TP=0, FP=0, FN=0, declined=True, error=None
- ai:qwen3:4b / test-two-leads: TP=2, FP=9, FN=0, declined=False, error=None
- hybrid:qwen3:4b / test-two-leads: TP=2, FP=9, FN=0, declined=False, error=None
- ai:qwen3:4b / test-safe-injection: TP=0, FP=1, FN=0, declined=False, error=None
- hybrid:qwen3:4b / test-safe-injection: TP=0, FP=1, FN=0, declined=False, error=None
- ai:qwen3:4b / test-invalid-python: TP=0, FP=0, FN=0, declined=False, error=None
- hybrid:qwen3:4b / test-invalid-python: TP=0, FP=0, FN=0, declined=False, error=None
- ai:qwen3:4b / test-comments: TP=0, FP=2, FN=0, declined=False, error=None
- hybrid:qwen3:4b / test-comments: TP=0, FP=2, FN=0, declined=False, error=None
- ai:qwen3:4b / test-cross-file-limit: TP=0, FP=11, FN=0, declined=False, error=None
- hybrid:qwen3:4b / test-cross-file-limit: TP=0, FP=11, FN=0, declined=False, error=None
