# ==============================================================================
# Stage 1: Builder - Compile rtl-sdr-blog (V4 support) and latest rtl_433
# ==============================================================================
FROM debian:bookworm-slim AS builder

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    cmake \
    git \
    pkg-config \
    libusb-1.0-0-dev \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# 1. Compile rtl-sdr-blog driver (Required for RTL-SDR Blog V4 R828D tuner)
WORKDIR /src/rtl-sdr-blog
RUN git clone --depth 1 https://github.com/rtlsdrblog/rtl-sdr-blog.git . \
    && mkdir build && cd build \
    && cmake ../ -DINSTALL_UDEV_RULES=ON -DDETACH_KERNEL_DRIVER=ON -DCMAKE_INSTALL_PREFIX=/usr/local \
    && make -j"$(nproc)" \
    && make install \
    && ldconfig

# 2. Compile latest rtl_433 linked against rtl-sdr-blog
WORKDIR /src/rtl_433
RUN git clone --depth 1 https://github.com/merbanan/rtl_433.git . \
    && mkdir build && cd build \
    && cmake ../ -DCMAKE_INSTALL_PREFIX=/usr/local \
    && make -j"$(nproc)" \
    && make install

# ==============================================================================
# Stage 2: Runtime - Clean Python 3.11 image with compiled SDR binaries
# ==============================================================================
FROM python:3.11-slim-bookworm

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    TZ=Europe/Stockholm

RUN apt-get update && apt-get install -y --no-install-recommends \
    libusb-1.0-0 \
    usbutils \
    bluez \
    dbus \
    libglib2.0-0 \
    tzdata \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Copy compiled libraries and binaries from builder stage
COPY --from=builder /usr/local/lib/librtlsdr* /usr/local/lib/
COPY --from=builder /usr/local/bin/rtl_433 /usr/local/bin/rtl_433
COPY --from=builder /usr/local/bin/rtl_test /usr/local/bin/rtl_test
COPY --from=builder /usr/local/bin/rtl_eeprom /usr/local/bin/rtl_eeprom
COPY --from=builder /usr/local/bin/rtl_fm /usr/local/bin/rtl_fm
COPY --from=builder /usr/local/bin/rtl_power /usr/local/bin/rtl_power

RUN ldconfig

WORKDIR /app

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r /app/requirements.txt

COPY app /app/app

RUN mkdir -p /app/data

ARG GIT_COMMIT=unknown
ARG BUILD_DATE=unknown
ENV GIT_COMMIT=${GIT_COMMIT}
ENV BUILD_DATE=${BUILD_DATE}

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8080/api/status || exit 1

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080", "--log-level", "info"]

