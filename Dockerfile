# VulScan v4.1.0 - Multi-stage Docker Build
# Next-Gen Web Security Scanner Container

# Build stage
FROM golang:1.23-alpine AS builder

# Set build arguments
ARG VERSION=4.1.0
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
    -ldflags="-w -s -X main.Version=${VERSION} -X main.BuildTime=${BUILD_TIME} -X main.GitCommit=${GIT_COMMIT}" \
    -trimpath \
    -o vulscan \
    main.go

# Verify the binary
RUN ./vulscan --version

# Production stage
FROM alpine:3.20

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

# Create configs directory
RUN mkdir -p /app/configs

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
LABEL description="VulScan v4.1.0 - Next-Gen Web Security Scanner with AI-Powered Detection"
LABEL org.opencontainers.image.title="VulScan"
LABEL org.opencontainers.image.description="Next-Gen Web Security Scanner with AI-Powered Detection for vulnerability assessment"
LABEL org.opencontainers.image.url="https://github.com/ATOMGAMERAGA/VulScan"
LABEL org.opencontainers.image.source="https://github.com/ATOMGAMERAGA/VulScan"
LABEL org.opencontainers.image.version="${VERSION}"
LABEL org.opencontainers.image.created="${BUILD_TIME}"
LABEL org.opencontainers.image.revision="${GIT_COMMIT}"
LABEL org.opencontainers.image.licenses="MIT"
