# Stage 1: Build Environment
FROM golang:1.26.1-alpine AS builder

# Set the working directory to where our code will live
WORKDIR /app/src

# Copy go.mod and go.sum first to leverage Docker layer caching
COPY src/go.mod src/go.sum ./
RUN go mod download

# Copy the rest of the application source code
COPY src/ ./

# Build the Go application securely (disabling CGO for a static binary)
ENV CGO_ENABLED=0 GOOS=linux GOARCH=amd64
RUN go build -o /recipe-api .

# Stage 2: Final Runtime Image
FROM gcr.io/distroless/static-debian12:nonroot

WORKDIR /

# Copy only the compiled binary from the builder stage
COPY --from=builder /recipe-api /recipe-api

# Enforce running as a non-root user
USER nonroot:nonroot

# Expose the application port
EXPOSE 8080

# Execute the Cobra application, defaulting to the 'serve' command
ENTRYPOINT ["/recipe-api"]
CMD ["serve"]
