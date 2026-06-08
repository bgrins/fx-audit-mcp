# Self-contained integration-test environment for fx-audit-mcp.
#
# Downloads a prebuilt mozilla-central ASAN fuzzing Firefox via fuzzfetch at
# image build time — no local Firefox build or external checkout required.
# The Firefox layer is cached by Docker; rebuild with --no-cache to refresh
# the browser build.
#
# Run from the repo root:
#   docker compose -f tests/integration/docker-compose.yml run --build --rm integration

FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

# Firefox runtime libraries + harness dependencies (xvfb for the headless X
# display grizzly uses on Linux, binutils for ffpuppet's addr2line
# symbolization fallback, procps for ps/top when debugging interactively).
RUN apt-get update && apt-get install -y --no-install-recommends \
    binutils \
    bzip2 \
    ca-certificates \
    dbus \
    fonts-liberation \
    libasound2t64 \
    libdbus-glib-1-2 \
    libgl1 \
    libgtk-3-0t64 \
    libpci3 \
    libpulse0 \
    libx11-xcb1 \
    libxt6t64 \
    procps \
    python3 \
    xvfb \
    xz-utils \
    && rm -rf /var/lib/apt/lists/*

COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /usr/local/bin/

# Download the latest mozilla-central ASAN fuzzing build (includes
# llvm-symbolizer, which ffpuppet uses for ASAN stack symbolization).
RUN uvx fuzzfetch --os Linux --cpu x86_64 --asan --fuzzing \
    -o /firefox -n firefox-asan

# Generous launch timeout: x86_64 ASAN Firefox may run under emulation
# (e.g. Rosetta on Apple Silicon) where startup is slower.
ENV FIREFOX_BINARY=/firefox/firefox-asan/firefox \
    FX_AUDIT_LAUNCH_TIMEOUT=120

WORKDIR /fx-audit-mcp

# Install dependencies first so source-only changes don't re-resolve them.
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --group dev --no-install-project

COPY . .
RUN uv sync --frozen --group dev

CMD ["uv", "run", "pytest", "-m", "integration", "-v"]
