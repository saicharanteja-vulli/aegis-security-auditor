# Repaired-case regression evaluation

v2 rerun of the original eight known-limit probes. Their unchanged labels informed the fixes, so this is development/regression evidence, not an independent test. The original failures are preserved in results/challenge.*. Original per-case rationales describe the v1 failure mechanisms.

- baseline / template-interpolation: TP=1, FP=0, FN=0, pass=True
- baseline / optional-eval: TP=0, FP=0, FN=1, pass=False
- baseline / default-node-import: TP=1, FP=0, FN=0, pass=True
- baseline / lambda-shadow: TP=0, FP=1, FN=0, pass=False
- baseline / comprehension-shadow: TP=0, FP=1, FN=0, pass=False
- baseline / unrelated-method: TP=0, FP=1, FN=0, pass=False
- baseline / regex-after-return: TP=0, FP=1, FN=0, pass=False
- baseline / namespace-reassignment: TP=0, FP=1, FN=0, pass=False
- static / template-interpolation: TP=1, FP=0, FN=0, pass=True
- static / optional-eval: TP=1, FP=0, FN=0, pass=True
- static / default-node-import: TP=1, FP=0, FN=0, pass=True
- static / lambda-shadow: TP=0, FP=0, FN=0, pass=True
- static / comprehension-shadow: TP=0, FP=0, FN=0, pass=True
- static / unrelated-method: TP=0, FP=0, FN=0, pass=True
- static / regex-after-return: TP=0, FP=0, FN=0, pass=True
- static / namespace-reassignment: TP=0, FP=0, FN=0, pass=True
