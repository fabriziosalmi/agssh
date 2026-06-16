package report

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// Digest returns the hex sha256 of b.
func Digest(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// DigestFile returns the hex sha256 of a file's contents.
func DigestFile(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return Digest(b), nil
}

// SignBlob signs payload with cosign (keyless OIDC in CI, or a configured key).
// An empty cosignPath or a signing failure is returned as an error, which at
// Gold makes AG-GOV-05 fail (fail-closed: an unsigned record is not authoritative).
func SignBlob(ctx context.Context, cosignPath string, payload []byte) (*Signature, error) {
	if cosignPath == "" {
		return nil, fmt.Errorf("cosign not found on PATH")
	}
	tmp, err := os.CreateTemp("", "agssh-record-*.json")
	if err != nil {
		return nil, err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(payload); err != nil {
		tmp.Close()
		return nil, err
	}
	tmp.Close()

	cmd := exec.CommandContext(ctx, cosignPath, "sign-blob", "--yes", tmp.Name())
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("cosign sign-blob: %w", err)
	}
	sig := strings.TrimSpace(string(out))
	if sig == "" {
		return nil, fmt.Errorf("cosign returned an empty signature")
	}
	return &Signature{Scheme: "cosign-sign-blob", Value: sig}, nil
}
