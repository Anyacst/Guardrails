"""Sample application for GuardX demo workspace."""

import os
from config import load_config


def main():
    cfg = load_config()
    print(f"App running in debug mode: {cfg.get('debug')}")


if __name__ == "__main__":
    main()
