# syntax=docker/dockerfile:1

# ─── Stage 1: Build ───────────────────────────────────────────────────────────
FROM golang:1.24-alpine AS builder

# Install git (needed by some Go modules)
RUN apk add --no-cache git

WORKDIR /build

# Copy dependency files first — better layer caching
# (only re-downloads deps when go.mod/go.sum change)
COPY src/go.mod src/go.sum ./
RUN go mod download

# Copy the rest of the source and build
COPY src/ .
RUN CGO_ENABLED=0 GOOS=linux go build -o /recipe-api .

# ─── Stage 2: Production ──────────────────────────────────────────────────────
# Distroless: no shell, no package manager, no curl, no wget
# Only the binary and minimal C libs survive into this image
FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=builder /recipe-api /recipe-api

# nonroot image already runs as non-root — make it explicit
USER nonroot:nonroot

EXPOSE 8080

ENTRYPOINT ["/recipe-api"]
CMD ["serve"]
