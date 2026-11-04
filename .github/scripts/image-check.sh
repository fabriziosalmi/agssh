#!/usr/bin/env bash
# Checks a built agssh image for properties `go test` cannot see, because they
# belong to the image and not to the code. ci.yml runs it on every PR against
# the image it just built; it runs the same way by hand:
#
#   docker build -t agssh:local . && .github/scripts/image-check.sh agssh:local
set -uo pipefail
img="${1:?usage: image-check.sh IMAGE}"
target="${TARGET:-https://agssh.dev/}"
fail=0

# TLS: the image must verify public certificates with its own CA bundle, with
# nothing mounted from the host. Exit 0 (conformant) and 1 (non-conformant) both
# mean the scan ran; anything else means it could not look.
out=$(docker run --rm "$img" scan -json "$target" 2>&1); rc=$?
if printf '%s' "$out" | grep -q 'x509:'; then
  echo "::error::$img cannot verify TLS certificates: $(printf '%s' "$out" | grep -o 'x509:[^"]*' | head -1)"
  fail=1
elif [ "$rc" -ne 0 ] && [ "$rc" -ne 1 ]; then
  echo "::error::scan $target exited $rc, want 0 or 1"
  printf '%s\n' "$out" | tail -20
  fail=1
else
  echo "ok: scan $target exited $rc using the image's own CA bundle"
fi

exit "$fail"
