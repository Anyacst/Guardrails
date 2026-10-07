"""Configuration loader for GuardX demo workspace."""

import os


def load_config():
    return {
        "api_key": os.getenv("DEMO_API_KEY", "default-test-key"),
        "db_pass": os.getenv("DATABASE_PASSWORD", "default-pass"),
        "debug": os.getenv("DEBUG", "false").lower() == "true",
    }
