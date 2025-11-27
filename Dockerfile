FROM python:3.10-slim AS builder

# Install required build tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3-dev \
    build-essential \
    libstdc++6 \
    libgcc-12-dev \
    patchelf \
    && rm -rf /var/lib/apt/lists/*

# Install Nuitka
RUN pip install --no-cache-dir nuitka

WORKDIR /app
COPY . /app

# Compile FastAPI app into binary
RUN nuitka --onefile --disable-console --output-dir=/app/build main.py

# ============================================================

FROM debian:bookworm-slim AS runtime

RUN apt-get update && apt-get install -y --no-install-recommends \
    libstdc++6 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=builder /app/build/main.bin /app/run_bin

EXPOSE 8000

CMD ["/app/run_bin"]
