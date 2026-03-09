# Stage 1: Build
FROM golang:1.22-alpine AS builder
WORKDIR /app
# Copy the source code from the src/ directory into the container
COPY src/ ./
RUN go mod download
RUN go build -o /main .

# Stage 2: Run
FROM gcr.io/distroless/static-debian12:nonroot
WORKDIR /app
# Copy only the compiled binary from the builder stage
COPY --from=builder /main /main
# Run as a non-root user for security
USER nonroot:nonroot
# Start the application
ENTRYPOINT ["/main"]
