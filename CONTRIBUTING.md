# Contributing

Thank you for your interest. This repository holds an individual proposal for
an AuthZEN profile, with an implementation and a conformance suite.
Contributions that improve the draft's clarity, the suite's rigour or
interoperability are welcome.

## Where things belong

- **The draft, the code, the tests or the docs in this repository:** open an
  issue or a pull request here.
- **A question for the AuthZEN Working Group** (how this profile should fit with
  its specifications): the group's
  [mailing list](https://lists.openid.net/mailman/listinfo/openid-specs-authzen)
  (taking part in the group requires the OpenID Foundation IPR Contribution
  Agreement).
- **Text for the draft:** contributions are accepted under Apache-2.0. The draft
  may be contributed to the AuthZEN Working Group, so if you propose draft text,
  please have signed the OpenID Foundation IPR Contribution Agreement
  (https://openid.net/intellectual-property/), or the text may need rewriting
  before then.
- **A suspected vulnerability:** report it privately; see `SECURITY.md`.

Everyone taking part is expected to follow the `CODE_OF_CONDUCT.md`
(Contributor Covenant 2.1).

## Before you open a pull request

The checks CI runs, on Linux, macOS and Windows:

```bash
python -m pip install -e ".[dev]"
python -m ruff check .
python -m mypy authzen_composition e2e
python -m pytest
PYTHONPATH=. python interop/verify_vectors.py
PYTHONPATH=. python scripts/gen_vectors.py --check
```

A change is ready when:

- **ruff** and **mypy** (strict) are clean;
- the suite passes at **100% line and branch coverage**, and new code comes with
  the tests that cover it;
- a change to a requirement of the draft updates its row in
  `docs/TRACEABILITY.md`, citing the tests that show it;
- a change to the scenarios regenerates the vectors with
  `scripts/gen_vectors.py`, never by hand;
- a change to the draft rebuilds `docs/authzen-composition-profile-1_0.txt`
  (see the README; CI checks that it is current).

The end-to-end run is slower and not part of every change:

```bash
PYTHONPATH=. python -m e2e.run_e2e
```
