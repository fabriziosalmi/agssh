# Contributing to agssh

Thanks for your interest. `agssh` is the deterministic, fail-closed runner for
**AGSSH-STD-001**. Contributions that keep it deterministic and the spec
single-sourced are very welcome.

## Prerequisites

- Go (see [`go.mod`](go.mod) for the exact version — CI uses `go-version-file`).
- For regenerating the standard: `python3` with `pip install weasyprint`.

## Build, test, lint

```sh
go build ./...
go test -race ./...
gofmt -l .        # must print nothing
go vet ./...
```

## The single-source rule (important)

The rules live as structured data in [`standard/build_pdf.py`](standard/build_pdf.py),
which emits **both** the rendered PDF **and** [`internal/rules/manifest.yaml`](internal/rules/manifest.yaml).
Never hand-edit `manifest.yaml`. Change the rules in `build_pdf.py`, then regenerate:

```sh
cd standard && python build_pdf.py
```

CI fails if `manifest.yaml` drifts from the generator (`skew_test.go` and a CI step
both enforce this).

## Pull requests

1. Branch off `main`.
2. Keep changes focused; add or update tests for behaviour changes.
3. Ensure `go test -race ./...`, `gofmt`, and `go vet` are clean.
4. Fill in the PR template. PRs require the `ci` check to pass and a review.

## Posture

`agssh` is fail-closed by design: a check that cannot conclusively verify must
return `INCONCLUSIVE`, never a silent `PASS`. Preserve that invariant in any new
checker.

## License

By contributing, you agree that your contributions are licensed under the
[Apache License 2.0](LICENSE).
