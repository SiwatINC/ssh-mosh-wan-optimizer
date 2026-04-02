# ── Stage 1: build / install Python dependencies ──────────────────────────────
FROM python:3.12-alpine AS builder

WORKDIR /build

RUN apk add --no-cache gcc musl-dev libffi-dev openssl-dev

COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt


# ── Stage 2: runtime ──────────────────────────────────────────────────────────
FROM python:3.12-alpine AS runtime

LABEL org.opencontainers.image.title="ssh-mosh-wan-optimizer"
LABEL org.opencontainers.image.description="SSH ↔ MOSH WAN Gateway"
LABEL org.opencontainers.image.source="https://github.com/siwatinc/ssh-mosh-wan-optimizer"

RUN apk add --no-cache mosh openssh-client

# Copy installed Python packages from builder
COPY --from=builder /install /usr/local

WORKDIR /app
COPY gateway/ gateway/
COPY main.py .

RUN mkdir -p /etc/gateway /keys && chmod 700 /etc/gateway /keys

EXPOSE 2222/tcp

ENV GATEWAY_HOST=0.0.0.0 \
    GATEWAY_PORT=2222 \
    GATEWAY_HOST_KEY_PATH=/etc/gateway/host_key \
    GATEWAY_AUTHORIZED_KEYS_PATH=/keys/authorized_keys

ENTRYPOINT ["python", "main.py"]
