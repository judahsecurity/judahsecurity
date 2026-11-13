FROM golang:1.24-alpine@sha256:8bee1901f1e530bfb4a7850aa7a479d17ae3a18beb6e09064ed54cfd245b7191 AS builder

RUN apk add --no-cache git ca-certificates

# Install vulnx CLI for enrichment tool exec fallback
RUN go install github.com/projectdiscovery/vulnx/v2/cmd/vulnx@latest

WORKDIR /build
COPY go.mod go.sum ./
# Download all modules declared in go.mod (verified against go.sum).
# We do NOT run go mod tidy here — tidy strips entries for packages it
# can't see yet (source hasn't been copied), which breaks the build.
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -ldflags="-s -w" -o aegis-oracle ./cmd/aegis-oracle && \
    go build -ldflags="-s -w" -o aegis-oracle-cli ./cmd/aegis-oracle-cli

# ── Runtime image ──────────────────────────────────────────────────────
FROM alpine:3.21@sha256:bc21487101ae47172509130ee1092cc273a831968d64b617776d1f69c81e42ab

RUN apk add --no-cache ca-certificates tzdata && \
    addgroup -S oracle && adduser -S oracle -G oracle

WORKDIR /app

COPY --from=builder /build/aegis-oracle          ./aegis-oracle
COPY --from=builder /build/aegis-oracle-cli      ./aegis-oracle-cli
COPY --from=builder /go/bin/vulnx              ./vulnx
COPY knowledgebase/                              ./knowledgebase/
COPY cmd/aegis-oracle/config.yaml               ./config.yaml

# Put vulnx on PATH so the react tool can exec it
ENV PATH="/app:${PATH}"

USER oracle

EXPOSE 8742

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD wget -qO- http://localhost:8742/health || exit 1

ENTRYPOINT ["./aegis-oracle"]
CMD ["-config", "config.yaml"]
