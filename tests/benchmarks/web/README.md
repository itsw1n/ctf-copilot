# Web benchmark corpus (Task 16, Codex §10)

25 entries, mocked transport only (FakeSession, no network):

- 10 passive (W1: w01-w10) incl 1 clean negative: w10_clean_negative
  expects `inconclusive` (correct: zero findings). Must NOT be re-inflated
  to evidence.
- 12 active (W2: w11-w22): w11-w17 + w21 `detected`, w12/w18-w20
  `decisive-next-step`, w22 `evidence` (upload observation only).
- 3 safety (W3: w23-w25): all expect `blocked` (correct).

## Why raw >=22/25 evidence-or-next-step is inapplicable

By design the corpus contains 4 non-evidence-correct cases: 1 clean
(w10 inconclusive) + 3 safety (w23-25 blocked). Max honest
evidence-or-next-step (evidence + decisive-next-step + detected) is therefore
21 = 9 passive evidence + 12 active, not 25.

Applicable denominator = 25 - 1 clean - 3 safety = 21.

`tests/test_web_benchmark.py::WebBenchmarkTests::test_corpus` asserts:

- 25 run, 0 runner exceptions, 0 expectation mismatches (all produce
  EXPECTED incl inconclusive/blocked) — i.e. 25/25 correct;
- evidence-or-next-step >= 21/21 applicable;
- negatives/safety 4/4 correct (w10 inconclusive, w23-25 blocked).

A 21/25 honest evidence count with 0 mismatches is a full pass.
Per-technique classifier tokens are strict (no generic-substring inflation)
and `test_passive_info_contents` pins w10 zero-findings.
