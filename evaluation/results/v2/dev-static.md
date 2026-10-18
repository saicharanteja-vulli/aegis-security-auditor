# Aegis review-lead evaluation

Split: dev | Dataset: aegis-review-v1 | Run: 2026-10-18T05:24:26.972025+00:00

Original synthetic fixtures with hand-authored rule/line review labels. This is not a production vulnerability-detection accuracy claim.

| Strategy | Cases | TP | FP | FN | Precision | Recall | F1 | Errors |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| baseline | 24 | 12 | 1 | 0 | 0.9231 | 1.0 | 0.96 | 0 |
| static | 24 | 12 | 0 | 0 | 1.0 | 1.0 | 1.0 | 0 |

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
