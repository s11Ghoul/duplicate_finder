FROM python:3.11-slim

ENV DEBIAN_FRONTEND=noninteractive
ENV DISPLAY=:99

# System dependencies: Chromium, VNC, noVNC, OpenVPN
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
    # OpenVPN (for Proton VPN connections)
    openvpn \
    # DNS handling for VPN
    openresolv \
    # Networking tools
    procps \
    iproute2 \
    iptables \
    net-tools \
    curl \
    # Supervisor
    supervisor \
    # Fonts for rendering
    fonts-liberation \
    fonts-noto-cjk \
    && rm -rf /var/lib/apt/lists/*

# Install update-resolv-conf script for OpenVPN DNS management
RUN if [ ! -f /etc/openvpn/update-resolv-conf ]; then \
        curl -sL https://raw.githubusercontent.com/alfredopalhares/openvpn-update-resolv-conf/master/update-resolv-conf.sh \
        -o /etc/openvpn/update-resolv-conf && \
        chmod +x /etc/openvpn/update-resolv-conf; \
    fi

WORKDIR /app

# Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY . .

# Create directories
RUN mkdir -p /app/results /app/vpn-configs

# Supervisor config
COPY supervisord.conf /etc/supervisor/conf.d/supervisord.conf

# Ports: Flask (5000), noVNC (6080)
EXPOSE 5000 6080

CMD ["/usr/bin/supervisord", "-c", "/etc/supervisor/conf.d/supervisord.conf"]
