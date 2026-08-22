#!/usr/bin/env python3
"""Inject generator-derived values into the hand-written docs.

The rule count, family count, standard version and PDF filename shown in
README.md / standard/README.md / action.yml / .airgap.yml are NOT hand-edited:
they are injected from standard/build_pdf.py (the single RULES/CHANGELOG
source) into marker-delimited spans (<!-- agssh:NAME -->...<!-- /agssh:NAME -->)
or, for YAML files that cannot carry HTML comments, into pattern-anchored
version strings.

    python3 standard/sync_readme.py          # rewrite the governed spans in place
    python3 standard/sync_readme.py --check  # CI gate: fail if any span is stale

Fail-closed by construction: an unreadable CHANGELOG, a missing marker, a
pattern that does not match exactly the expected number of times, or a missing
rendered PDF all exit nonzero. --check prints an explicit verdict on success —
it never passes silently.
"""
import os
import re
import sys

_here = os.path.dirname(os.path.abspath(__file__))
_root = os.path.abspath(os.path.join(_here, ".."))
sys.path.insert(0, _here)


def die(msg, code=2):
    print("sync_readme: FAIL — %s" % msg, file=sys.stderr)
    raise SystemExit(code)


# Importing the generator computes n_rules/n_fam/DOC_VER from the RULES
# structure and CHANGELOG.md (and regenerates its artifacts as a side effect).
# Any failure in it propagates as a nonzero exit — fail-closed.
import build_pdf as bp  # noqa: E402

PDF = os.path.basename(bp.pdf_path)
if not os.path.exists(os.path.join(_root, "standard", PDF)):
    die("standard/%s does not exist — the CHANGELOG says %s but the rendered "
        "PDF was not regenerated (cd standard && pip install weasyprint && "
        "python build_pdf.py)" % (PDF, bp.DOC_VER))

# Marker-delimited spans: {relpath: {marker name: (expected count, content)}}.
SPANS = {
    "README.md": {
        "std-headline": (1, "[`standard/%s`](standard/%s) — %d rules across %d families"
                         % (PDF, PDF, bp.n_rules, bp.n_fam)),
        "n-rules": (1, str(bp.n_rules)),
    },
    "standard/README.md": {
        "std-pdf": (1, "`%s`" % PDF),
    },
}

# Pattern-anchored rewrites for files where an HTML comment cannot live.
PATTERNS = {
    "action.yml": (r"AGSSH-STD-001 v\d+\.\d+\.\d+", "AGSSH-STD-001 " + bp.DOC_VER, 1),
    ".airgap.yml": (r"AGSSH-STD-001 v\d+\.\d+\.\d+", "AGSSH-STD-001 " + bp.DOC_VER, 1),
}


def synced(rel, text):
    """Return text with every governed span/pattern set to its derived value."""
    for name, (want, content) in SPANS.get(rel, {}).items():
        pat = re.compile(r"(<!-- agssh:%s -->).*?(<!-- /agssh:%s -->)"
                         % (re.escape(name), re.escape(name)), re.S)
        n = len(pat.findall(text))
        if n != want:
            die("%s: marker agssh:%s found %d time(s), expected %d" % (rel, name, n, want))
        text = pat.sub(lambda m: m.group(1) + content + m.group(2), text)
    if rel in PATTERNS:
        raw, repl, want = PATTERNS[rel]
        pat = re.compile(raw)
        n = len(pat.findall(text))
        if n != want:
            die("%s: pattern %r found %d time(s), expected %d" % (rel, raw, n, want))
        text = pat.sub(repl, text)
    return text


def main():
    check = "--check" in sys.argv[1:]
    files = sorted(set(SPANS) | set(PATTERNS))
    stale = []
    for rel in files:
        path = os.path.join(_root, rel)
        try:
            with open(path, encoding="utf-8") as f:
                cur = f.read()
        except OSError as e:
            die("cannot read %s: %s" % (rel, e))
        new = synced(rel, cur)
        if new != cur:
            stale.append(rel)
            if not check:
                with open(path, "w", encoding="utf-8") as f:
                    f.write(new)

    summary = "%d rules · %d families · %s · %s" % (bp.n_rules, bp.n_fam, bp.DOC_VER, PDF)
    if check:
        if stale:
            for rel in stale:
                print("sync_readme: STALE — %s does not match the generator" % rel,
                      file=sys.stderr)
            die("stale derived values (%s); run: python3 standard/sync_readme.py"
                % summary, code=1)
        print("sync_readme: OK — %s in sync with the generator: %s"
              % (", ".join(files), summary))
    else:
        for rel in stale:
            print("sync_readme: rewrote %s" % rel)
        print("sync_readme: OK — %s" % summary)


main()
