# Dockerfile for hardened-photo-server
# Builds the C HTTPS server and runs it as a non-root user.

FROM debian:bookworm-slim

# Build arguments (can be overridden from Makefile)
ARG PORT=443
ARG PHOTOS_DIR=./photos

ENV PORT=${PORT}
ENV PHOTOS_DIR=${PHOTOS_DIR}
ENV APP_PASSWORD=password

# Install build/runtime dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        gcc make \
        libssl-dev libjpeg-dev \
        openssl ca-certificates \
        curl \
    && rm -rf /var/lib/apt/lists/*

# App source
WORKDIR /app
COPY . .

# Create photos directory and non-root user
RUN mkdir -p "${PHOTOS_DIR}" && \
    groupadd -r photo && useradd -r -g photo photo && \
    chown -R photo:photo "${PHOTOS_DIR}" /app

# Generate self-signed TLS cert for localhost
RUN openssl req -x509 -newkey rsa:2048 \
      -keyout server.key -out server.crt \
      -days 365 -nodes \
      -subj "/C=US/ST=None/L=None/O=SelfSigned/CN=localhost"

# Build the server with container-specific PORT & PHOTOS_DIR
RUN make clean || true && \
    make build PHOTOS_DIR=${PHOTOS_DIR} PORT=${PORT}

USER photo

EXPOSE ${PORT}

CMD ["./httpsetup"]
