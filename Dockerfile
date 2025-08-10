# VulScan v3.0 - Multi-stage Docker Build
# Advanced Web Security Scanner Container

# Build stage
FROM golang:1.21-alpine AS builder

# Set build arguments
ARG VERSION=dev
ARG BUILD_TIME
ARG GIT_COMMIT

# Install build dependencies
RUN apk add --no-cache \
    git \
    ca-certificates \
    tzdata \
    make

# Set working directory
WORKDIR /build

# Copy go mod files first for better caching
COPY go.mod go.sum ./
RUN go mod download && go mod verify

# Copy source code
COPY . .

# Build the application with optimization flags
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags="-w -s -X main.version=${VERSION} -X main.buildTime=${BUILD_TIME} -X main.gitCommit=${GIT_COMMIT}" \
    -trimpath \
    -o vulscan \
    main.go

# Verify the binary
RUN ./vulscan --help

# Production stage
FROM alpine:3.19

# Install runtime dependencies
RUN apk add --no-cache \
    ca-certificates \
    tzdata \
    curl \
    jq \
    && rm -rf /var/cache/apk/*

# Create non-root user for security
RUN addgroup -g 1000 -S vulscan && \
    adduser -u 1000 -S vulscan -G vulscan

# Set working directory
WORKDIR /app

# Copy binary from builder stage
COPY --from=builder /build/vulscan /app/vulscan

# Create directories for reports and configs
RUN mkdir -p /app/reports /app/configs && \
    chown -R vulscan:vulscan /app

# Copy configuration files if they exist
COPY --chown=vulscan:vulscan configs/ /app/configs/ 2>/dev/null || true

# Switch to non-root user
USER vulscan

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD ["/app/vulscan", "--help"]

# Set environment variables
ENV VULSCAN_OUTPUT_DIR=/app/reports
ENV VULSCAN_CONFIG_DIR=/app/configs

# Default command
ENTRYPOINT ["/app/vulscan"]
CMD ["--help"]

# Metadata
LABEL maintainer="ATOMGAMERAGA <atomgameraga@atomland.xyz>"
LABEL version="${VERSION}"
LABEL description="VulScan v3.0 - Advanced Web Security Scanner"
LABEL org.opencontainers.image.title="VulScan"
LABEL org.opencontainers.image.description="Advanced Web Security Scanner for vulnerability assessment"
LABEL org.opencontainers.image.url="https://github.com/ATOMGAMERAGA/VulScan"
LABEL org.opencontainers.image.source="https://github.com/ATOMGAMERAGA/VulScan"
LABEL org.opencontainers.image.version="${VERSION}"
LABEL org.opencontainers.image.created="${BUILD_TIME}"
LABEL org.opencontainers.image.revision="${GIT_COMMIT}"
LABEL org.opencontainers.image.licenses="MIT"
