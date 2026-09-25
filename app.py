"""CSPM launcher.

Usage examples:
    python app.py
    python app.py --mode cli
    python app.py --mode dashboard
    python app.py --mode dashboard --port 8502
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def run_cli() -> int:
    print("Starting CSPM command-line workflow...")
    cmd = [sys.executable, "main.py", "--mode", "demo"]
    return subprocess.run(cmd, cwd=str(ROOT), check=False).returncode


def run_dashboard(port: int = 8501) -> int:
    print(f"Starting CSPM dashboard on http://localhost:{port}")
    cmd = [
        sys.executable,
        "-m",
        "streamlit",
        "run",
        "dashboard.py",
        "--server.headless",
        "true",
        "--server.port",
        str(port),
    ]
    return subprocess.run(cmd, cwd=str(ROOT), check=False).returncode


def interactive_menu() -> int:
    print("\n=== CSPM Application ===")
    print("1. Run CLI scan")
    print("2. Launch dashboard")
    print("3. Exit")

    choice = input("Select an option [1-3]: ").strip()

    if choice == "1":
        return run_cli()
    if choice == "2":
        return run_dashboard()
    if choice == "3":
        print("Goodbye.")
        return 0

    print("Invalid selection. Please choose 1, 2, or 3.")
    return 1


def main() -> int:
    parser = argparse.ArgumentParser(description="CSPM application launcher")
    parser.add_argument(
        "--mode",
        choices=["cli", "dashboard", "menu"],
        default=None,
        help="Choose which interface to launch. Omitting this opens the interactive menu.",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8501,
        help="Port used by the Streamlit dashboard.",
    )
    args = parser.parse_args()

    if args.mode is None:
        return interactive_menu()
    if args.mode == "cli":
        return run_cli()
    if args.mode == "menu":
        return interactive_menu()
    return run_dashboard(port=args.port)


if __name__ == "__main__":
    raise SystemExit(main())
