# AGSSH-STD-001 — the standard

<!-- agssh:std-pdf -->`AGSSH-STD-001-v1.5.0.pdf`<!-- /agssh:std-pdf --> is the rendered standard. `build_pdf.py` is its
canonical source: the rules are structured data in this script, which emits both
the PDF and (the basis for) the runner's rule manifest. Edit rules here so the
document and the `agssh` runner stay in sync.

## Regenerate

```bash
pip install weasyprint
python build_pdf.py        # renders the versioned PDF next to this file
python sync_readme.py      # re-injects derived counts/versions into the docs
```

`build_pdf.py` writes the HTML and, if `weasyprint` is available, renders the PDF
directly — byte-reproducibly: `SOURCE_DATE_EPOCH` defaults to the release date,
so regenerating the same release yields identical bytes.
`DOC_VER`/`DOC_DATE` — and therefore the output filename — are derived
from the newest release heading of `CHANGELOG.md`, never hand-bumped: cut a
release there and the document, the runner's version constant and the docs (via
`sync_readme.py`) all follow. The standard's SemVer discipline still applies to
rule changes (new rule/profile = MINOR; tightened or removed MUST = MAJOR).
