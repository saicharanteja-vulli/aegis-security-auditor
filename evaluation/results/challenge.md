# Known-limit challenge probes

Post-test known-limit probes, separate from the 72-case comparison; no model calls, no detector tuning. These failures bound the meaning of the perfect main synthetic static score.

- baseline / template-interpolation: TP=1, FP=0, FN=0. Template interpolation is masked together with literal template text.
- baseline / optional-eval: TP=0, FP=0, FN=1. Optional call syntax is outside the current regex.
- baseline / default-node-import: TP=1, FP=0, FN=0. Default-import Node alias is not modeled.
- baseline / lambda-shadow: TP=0, FP=1, FN=0. Lambda varargs shadow a builtin; current lambda visitor does not bind varargs.
- baseline / comprehension-shadow: TP=0, FP=1, FN=0. Comprehension target shadows the module; scope is not modeled.
- baseline / unrelated-method: TP=0, FP=1, FN=0. A method called eval is not the global JavaScript builtin.
- baseline / regex-after-return: TP=0, FP=1, FN=0. The lexical slash heuristic misses regex after return.
- baseline / namespace-reassignment: TP=0, FP=1, FN=0. Node alias reassignment is not modeled; the custom adapter method is not a known shell API.
- static / template-interpolation: TP=0, FP=0, FN=1. Template interpolation is masked together with literal template text.
- static / optional-eval: TP=0, FP=0, FN=1. Optional call syntax is outside the current regex.
- static / default-node-import: TP=0, FP=0, FN=1. Default-import Node alias is not modeled.
- static / lambda-shadow: TP=0, FP=1, FN=0. Lambda varargs shadow a builtin; current lambda visitor does not bind varargs.
- static / comprehension-shadow: TP=0, FP=1, FN=0. Comprehension target shadows the module; scope is not modeled.
- static / unrelated-method: TP=0, FP=1, FN=0. A method called eval is not the global JavaScript builtin.
- static / regex-after-return: TP=0, FP=1, FN=0. The lexical slash heuristic misses regex after return.
- static / namespace-reassignment: TP=0, FP=1, FN=0. Node alias reassignment is not modeled; the custom adapter method is not a known shell API.
