FROM python:3.10-slim AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    python3-dev \
    build-essential \
    patchelf \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
RUN pip install --no-cache-dir nuitka

COPY . .

# Kompilasi run.py
# --follow-imports: Mencari semua file yang di-import (seperti main.py)
# --include-package=app: Memastikan folder 'app' dan isinya ikut masuk ke binary
RUN python -m nuitka --onefile \
    --follow-imports \
    --include-package=app \
    --output-filename=elastic_bin \
    --output-dir=build \
    run.py

# ============================================================

FROM debian:bookworm-slim AS runtime

WORKDIR /app
# Salin binary yang sudah jadi
COPY --from=builder /app/build/elastic_bin /app/elastic_bin

# Expose port Backend Utama
EXPOSE 8000

# Jalankan binary tunggal
CMD ["/app/elastic_bin"]