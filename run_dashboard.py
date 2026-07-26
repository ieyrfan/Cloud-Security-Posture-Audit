#!/usr/bin/env python3
"""
Security Dashboard Launcher
Runs the Streamlit dashboard for security posture visualization.
"""

import subprocess
import sys
import os

def main():
    dashboard_dir = os.path.dirname(os.path.abspath(__file__))
    app_path = os.path.join(dashboard_dir, "app.py")

    print("=" * 60)
    print("Cloud Security Posture Dashboard")
    print("=" * 60)
    print()
    print("Starting dashboard...")
    print(f"Dashboard path: {app_path}")
    print()
    print("Open browser to: http://localhost:8501")
    print("Press Ctrl+C to stop")
    print("=" * 60)
    print()

    cmd = [
        sys.executable, "-m", "streamlit", "run",
        app_path,
        "--server.port=8501",
        "--server.headless=true",
        "--browser.gatherUsageStats=false"
    ]

    try:
        subprocess.run(cmd, check=True)
    except KeyboardInterrupt:
        print("\n[+] Dashboard stopped.")
    except FileNotFoundError:
        print("[!] Streamlit not installed. Install with: pip install streamlit plotly")
        print("    Then run: python run_dashboard.py")
        sys.exit(1)

if __name__ == '__main__':
    main()
