#!/usr/bin/env python3
"""Entry point for the Phishing Detector web application."""

import os

from webapp.app import create_app

app = create_app()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False, threaded=True)
