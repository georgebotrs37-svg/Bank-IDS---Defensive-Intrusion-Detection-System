import subprocess
import sys
import time
import os

def main():
    print("=" * 70)
    print("      MR.X BANK SOC SENTINEL - ENTERPRISE SECURITY SYSTEM")
    print("=" * 70)
    print("Starting FastAPI Backend Server on http://127.0.0.1:8000 ...")

    # Start FastAPI
    backend_proc = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "main:app", "--host", "127.0.0.1", "--port", "8000"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True
    )

    print("FastAPI process started. Waiting 3 seconds for database initialization...")
    time.sleep(3)

    print("Starting Streamlit SOC Analyst Dashboard on http://localhost:8501 ...")
    streamlit_proc = subprocess.Popen(
        [sys.executable, "-m", "streamlit", "run", "frontend/app.py", "--server.port=8501", "--server.headless=true"],
        text=True
    )

    print("\n" + "=" * 70)
    print("  MR.X BANK SOC SENTINEL IS LIVE!")
    print("  - Backend REST API & Docs: http://127.0.0.1:8000/docs")
    print("  - Streamlit SOC Dashboard: http://localhost:8501")
    print("=" * 70)
    print("Press Ctrl+C to terminate both services.\n")

    try:
        streamlit_proc.wait()
    except KeyboardInterrupt:
        print("\nShutting down SOC Sentinel services...")
        streamlit_proc.terminate()
        backend_proc.terminate()
        print("Shutdown complete.")

if __name__ == "__main__":
    main()

