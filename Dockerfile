FROM python:3.11-slim

ENV DEBIAN_FRONTEND=noninteractive
ENV DISPLAY=:99

# System dependencies: Chromium, VNC, noVNC, VPN
RUN apt-get update && apt-get install -y --no-install-recommends \
    # Chromium
    chromium \
    chromium-driver \
    # Virtual display + VNC
    xvfb \
    x11vnc \
    # noVNC
    novnc \
    websockify \
    # VPN dependencies
    openvpn \
    procps \
    iproute2 \
    iptables \
    net-tools \
    curl \
    gnupg \
    # Supervisor
    supervisor \
    # Fonts for rendering
    fonts-liberation \
    fonts-noto-cjk \
    && rm -rf /var/lib/apt/lists/*

# Install Proton VPN CLI
RUN pip install --no-cache-dir protonvpn-cli

WORKDIR /app

# Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY . .

# Create results directory
RUN mkdir -p /app/results

# Supervisor config
COPY supervisord.conf /etc/supervisor/conf.d/supervisord.conf

# Ports: Flask (5000), noVNC (6080)
EXPOSE 5000 6080

CMD ["/usr/bin/supervisord", "-c", "/etc/supervisor/conf.d/supervisord.conf"]
