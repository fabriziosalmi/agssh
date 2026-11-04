# syntax=docker/dockerfile:1
# ---- build the static runner ----
# Pin the builder by digest in production (AG-SUP-03 / AG-GOV-07).
FROM golang:1.26 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /agssh ./cmd/agssh

# ---- cosign for the signed attestation (AG-GOV-05) ----
FROM gcr.io/projectsigstore/cosign:v2.4.1 AS cosign

# ---- runtime: headless-shell provides Chromium for the dynamic plane ----
# Pinned by tag + digest so the image is reproducible (AG-SUP-03).
FROM chromedp/headless-shell:148.0.7778.97@sha256:313ed7255ae1e155fb157631a6d4c0eb8b65bbe06de9e704ed834399bdf678ff
ENV AGSSH_CHROME=/headless-shell/headless-shell
# headless-shell ships no CA bundle (no /etc/ssl at all), so Go's crypto/x509
# could verify no certificate and every https surface was UNSCANNABLE. Take the
# Debian bundle from the build stage, at the first path Go looks for on Linux.
COPY --from=build  /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build  /agssh           /usr/local/bin/agssh
COPY --from=cosign /ko-app/cosign   /usr/local/bin/cosign
WORKDIR /github/workspace
ENTRYPOINT ["/usr/local/bin/agssh"]
