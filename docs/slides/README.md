# SLH-DSA signing and verification, step by step (Beamer)

`slh-dsa-sign-verify.tex` walks through FIPS 205 pure signing (Algorithms 22 and 19) and
verification (Algorithms 24 and 20) on one SLH-DSA-SHAKE-128f signature. Every value on the
slides comes from that signature.

| File | What it is |
| --- | --- |
| `slh-dsa-sign-verify.tex` / `.pdf` | The deck: 31 slides, 16:9 |
| `running_example.json` | Key pair (seeds `00..2f`), message, context and signature from `slhsig` |
| `trace.py` | A separate Python implementation of FIPS 205 for the SHAKE-128f set |
| `trace.json` | Its output: intermediate values and hash-call counts used in the slides |

The example key is derived from public, fixed seeds. It is for illustration only.

## Reproduce

```sh
cargo run --example running_example > docs/slides/running_example.json
python3 docs/slides/trace.py docs/slides/running_example.json > docs/slides/trace.json
cd docs/slides && tectonic slh-dsa-sign-verify.tex
```

`trace.py` re-derives PK.root from the seeds, re-signs, checks that its signature is
byte-identical to slhsig's, verifies it, and records the trace. It exits with an assertion
error if any of those checks fails.
