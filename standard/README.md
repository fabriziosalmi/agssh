# AGSSH-STD-001 — the standard

`AGSSH-STD-001-v1.0.0.pdf` is the rendered standard. `build_pdf.py` is its
canonical source: the rules are structured data in this script, which emits both
the PDF and (the basis for) the runner's rule manifest. Edit rules here so the
document and the `agssh` runner stay in sync.

## Regenerate

```bash
pip install weasyprint
python build_pdf.py        # writes AGSSH-STD-001-v1.0.0.pdf next to this file
```

`build_pdf.py` writes the HTML and, if `weasyprint` is available, renders the PDF
directly. The version string (`DOC_VER`) drives the output filename; bump it per
Semantic Versioning when you change rules (new rule/profile = MINOR; tightened or
removed MUST = MAJOR).
