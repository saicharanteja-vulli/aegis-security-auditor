# Aegis review-lead evaluation

Split: dev | Dataset: aegis-review-v1 | Run: 2026-10-18T05:04:50.442891+00:00

Original synthetic fixtures with hand-authored rule/line review labels. This is not a production vulnerability-detection accuracy claim.

| Strategy | Cases | TP | FP | FN | Precision | Recall | F1 | Errors |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| baseline | 24 | 12 | 1 | 0 | 0.9231 | 1.0 | 0.96 | 0 |
| static | 24 | 12 | 0 | 0 | 1.0 | 1.0 | 1.0 | 0 |
| ai:qwen3:1.7b | 24 | 0 | 0 | 12 | None | 0.0 | 0.0 | 21 |
| hybrid:qwen3:1.7b | 24 | 12 | 0 | 0 | 1.0 | 1.0 | 1.0 | 21 |

## What is measured

- A true positive matches the expected rule AND exact source line. Wrong-line predictions count as false positives and leave a missed expected finding.
- Invalid AI proposals count as false positives in the benchmark, even though the application withholds them. Duplicate valid identities are deduplicated and recorded.
- Model errors leave positive findings missed and are never counted as successful clean reviews. Unreviewed negative cases remain in the specificity denominator.
- Hybrid is the union of current static findings and source-validated AI leads. It never removes a static finding. AI and hybrid use the same model response per case.
- Labels describe local review patterns, not proven exploitability. All fixtures are synthetic and public; dev/test variants share rule families. The benchmark was co-designed with the implementation, so it is not independent generalization evidence.
- Precision/recall do not measure explanation entailment or whether a suggested fix works. The full source, labels, accepted findings, rejected proposals, raw model responses and usage are retained in JSON.
- Timing is one development-machine sample with cache/load effects and other verification activity; do not infer a universal model or performance ranking.

## Misses and false positives

- baseline / js003-negative-1: TP=0, FP=1, FN=0, declined=False, error=None
- ai:qwen3:1.7b / py001-positive-1: TP=0, FP=0, FN=1, declined=False, error=ReviewValidationError: Unreviewable responses cannot contain findings.
- hybrid:qwen3:1.7b / py001-positive-1: TP=1, FP=0, FN=0, declined=False, error=ReviewValidationError: Unreviewable responses cannot contain findings.
- ai:qwen3:1.7b / py001-negative-1: TP=0, FP=0, FN=0, declined=False, error=ReviewValidationError: Unreviewable responses cannot contain findings.
- hybrid:qwen3:1.7b / py001-negative-1: TP=0, FP=0, FN=0, declined=False, error=ReviewValidationError: Unreviewable responses cannot contain findings.
- ai:qwen3:1.7b / py002-positive-1: TP=0, FP=0, FN=1, declined=False, error=ReviewValidationError: Unreviewable responses cannot contain findings.
- hybrid:qwen3:1.7b / py002-positive-1: TP=1, FP=0, FN=0, declined=False, error=ReviewValidationError: Unreviewable responses cannot contain findings.
- ai:qwen3:1.7b / py002-negative-1: TP=0, FP=0, FN=0, declined=True, error=None
- hybrid:qwen3:1.7b / py002-negative-1: TP=0, FP=0, FN=0, declined=True, error=None
- ai:qwen3:1.7b / py003-positive-1: TP=0, FP=0, FN=1, declined=False, error=ReviewValidationError: Unreviewable responses cannot contain findings.
- hybrid:qwen3:1.7b / py003-positive-1: TP=1, FP=0, FN=0, declined=False, error=ReviewValidationError: Unreviewable responses cannot contain findings.
- ai:qwen3:1.7b / py003-negative-1: TP=0, FP=0, FN=0, declined=False, error=ReviewValidationError: Unreviewable responses cannot contain findings.
- hybrid:qwen3:1.7b / py003-negative-1: TP=0, FP=0, FN=0, declined=False, error=ReviewValidationError: Unreviewable responses cannot contain findings.
- ai:qwen3:1.7b / py004-positive-1: TP=0, FP=0, FN=1, declined=False, error=ReviewValidationError: Unreviewable responses cannot contain findings.
- hybrid:qwen3:1.7b / py004-positive-1: TP=1, FP=0, FN=0, declined=False, error=ReviewValidationError: Unreviewable responses cannot contain findings.
- ai:qwen3:1.7b / py004-negative-1: TP=0, FP=0, FN=0, declined=False, error=ReviewValidationError: Unreviewable responses cannot contain findings.
- hybrid:qwen3:1.7b / py004-negative-1: TP=0, FP=0, FN=0, declined=False, error=ReviewValidationError: Unreviewable responses cannot contain findings.
- ai:qwen3:1.7b / py005-positive-1: TP=0, FP=0, FN=1, declined=False, error=ReviewValidationError: Unreviewable responses cannot contain findings.
- hybrid:qwen3:1.7b / py005-positive-1: TP=1, FP=0, FN=0, declined=False, error=ReviewValidationError: Unreviewable responses cannot contain findings.
- ai:qwen3:1.7b / py005-negative-1: TP=0, FP=0, FN=0, declined=False, error=ReviewValidationError: Unreviewable responses cannot contain findings.
- hybrid:qwen3:1.7b / py005-negative-1: TP=0, FP=0, FN=0, declined=False, error=ReviewValidationError: Unreviewable responses cannot contain findings.
- ai:qwen3:1.7b / py006-positive-1: TP=0, FP=0, FN=1, declined=True, error=None
- hybrid:qwen3:1.7b / py006-positive-1: TP=1, FP=0, FN=0, declined=True, error=None
- ai:qwen3:1.7b / py006-negative-1: TP=0, FP=0, FN=0, declined=False, error=ReviewValidationError: Unreviewable responses cannot contain findings.
- hybrid:qwen3:1.7b / py006-negative-1: TP=0, FP=0, FN=0, declined=False, error=ReviewValidationError: Unreviewable responses cannot contain findings.
- ai:qwen3:1.7b / sec001-positive-1: TP=0, FP=0, FN=1, declined=False, error=ReviewValidationError: Unreviewable responses cannot contain findings.
- hybrid:qwen3:1.7b / sec001-positive-1: TP=1, FP=0, FN=0, declined=False, error=ReviewValidationError: Unreviewable responses cannot contain findings.
- ai:qwen3:1.7b / sec001-negative-1: TP=0, FP=0, FN=0, declined=False, error=ReviewValidationError: Unreviewable responses cannot contain findings.
- hybrid:qwen3:1.7b / sec001-negative-1: TP=0, FP=0, FN=0, declined=False, error=ReviewValidationError: Unreviewable responses cannot contain findings.
- ai:qwen3:1.7b / js001-positive-1: TP=0, FP=0, FN=1, declined=False, error=ReviewValidationError: Unreviewable responses cannot contain findings.
- hybrid:qwen3:1.7b / js001-positive-1: TP=1, FP=0, FN=0, declined=False, error=ReviewValidationError: Unreviewable responses cannot contain findings.
- ai:qwen3:1.7b / js001-negative-1: TP=0, FP=0, FN=0, declined=False, error=ReviewValidationError: Unreviewable responses cannot contain findings.
- hybrid:qwen3:1.7b / js001-negative-1: TP=0, FP=0, FN=0, declined=False, error=ReviewValidationError: Unreviewable responses cannot contain findings.
- ai:qwen3:1.7b / js002-positive-1: TP=0, FP=0, FN=1, declined=False, error=ReviewValidationError: Unreviewable responses cannot contain findings.
- hybrid:qwen3:1.7b / js002-positive-1: TP=1, FP=0, FN=0, declined=False, error=ReviewValidationError: Unreviewable responses cannot contain findings.
- ai:qwen3:1.7b / js002-negative-1: TP=0, FP=0, FN=0, declined=False, error=ReviewValidationError: Unreviewable responses cannot contain findings.
- hybrid:qwen3:1.7b / js002-negative-1: TP=0, FP=0, FN=0, declined=False, error=ReviewValidationError: Unreviewable responses cannot contain findings.
- ai:qwen3:1.7b / js003-positive-1: TP=0, FP=0, FN=1, declined=False, error=ReviewValidationError: Unreviewable responses cannot contain findings.
- hybrid:qwen3:1.7b / js003-positive-1: TP=1, FP=0, FN=0, declined=False, error=ReviewValidationError: Unreviewable responses cannot contain findings.
- ai:qwen3:1.7b / js003-negative-1: TP=0, FP=0, FN=0, declined=False, error=ReviewValidationError: Unreviewable responses cannot contain findings.
- hybrid:qwen3:1.7b / js003-negative-1: TP=0, FP=0, FN=0, declined=False, error=ReviewValidationError: Unreviewable responses cannot contain findings.
- ai:qwen3:1.7b / cfg001-positive-1: TP=0, FP=0, FN=1, declined=False, error=ReviewValidationError: Unreviewable responses cannot contain findings.
- hybrid:qwen3:1.7b / cfg001-positive-1: TP=1, FP=0, FN=0, declined=False, error=ReviewValidationError: Unreviewable responses cannot contain findings.
- ai:qwen3:1.7b / cfg001-negative-1: TP=0, FP=0, FN=0, declined=False, error=ReviewValidationError: Unreviewable responses cannot contain findings.
- hybrid:qwen3:1.7b / cfg001-negative-1: TP=0, FP=0, FN=0, declined=False, error=ReviewValidationError: Unreviewable responses cannot contain findings.
- ai:qwen3:1.7b / dev-injection: TP=0, FP=0, FN=1, declined=False, error=ReviewValidationError: Unreviewable responses cannot contain findings.
- hybrid:qwen3:1.7b / dev-injection: TP=1, FP=0, FN=0, declined=False, error=ReviewValidationError: Unreviewable responses cannot contain findings.
