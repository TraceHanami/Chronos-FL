"""
Unified CLI Entrypoint for CHRONOS-FL.
"""

from __future__ import annotations
import argparse
import time
import uvicorn
from chronos.system.collector import EvidenceCollector
from chronos.system.live_sensor import LiveHostSensor
from chronos.research.trust_engine import TrustAnalysisEngine
from chronos.config.settings import get_settings


def main():
    settings = get_settings()
    parser = argparse.ArgumentParser(description="CHRONOS-FL Cyber Forensic Flight Recorder CLI")
    subparsers = parser.add_subparsers(dest="command", help="Sub-command to run")

    subparsers.add_parser("status", help="Display flight recorder status and live host telemetry")
    subparsers.add_parser("monitor", help="Start real-time live host sensor monitoring")
    subparsers.add_parser("demo", help="Run end-to-end forensic flight recorder demonstration")
    subparsers.add_parser("sim", help="Simulate attack & anti-forensic evidence destruction")

    serve_parser = subparsers.add_parser("serve", help="Start FastAPI Investigation Dashboard server")
    serve_parser.add_argument("--port", type=int, default=settings.API_PORT, help="Port to listen on")
    serve_parser.add_argument("--host", type=str, default=settings.API_HOST, help="Host interface to bind")

    args = parser.parse_args()

    if args.command == "status":
        print("=" * 70)
        print("      CHRONOS-FL — DIGITAL FORENSIC FLIGHT RECORDER STATUS")
        print("=" * 70)
        collector = EvidenceCollector(host_id=settings.HOST_ID)
        sensor = LiveHostSensor(collector)
        print("[*] Scanning running processes on host...")
        sensor.scan_running_processes()
        print(f"[+] Discovered {len(collector.events)} active processes.")
        
        ess = TrustAnalysisEngine().compute_ess([])
        tcs = TrustAnalysisEngine().compute_tcs(ess, [])
        print(f"[+] Baseline ESS (Evidence Survivability Score): {ess.ess_score}%")
        print(f"[+] Baseline TCS (Timeline Confidence Score): {tcs.tcs_score}% ({tcs.confidence_level})")

    elif args.command == "monitor":
        print("[*] Starting live OS telemetry monitor... (Press Ctrl+C to stop)")
        collector = EvidenceCollector(host_id=settings.HOST_ID)
        sensor = LiveHostSensor(collector)
        sensor.scan_running_processes()
        try:
            while True:
                sensor.scan_network_connections()
                time.sleep(2)
        except KeyboardInterrupt:
            print("\n[+] Monitoring stopped.")

    elif args.command == "demo":
        from scripts.demo_full_pipeline import run_chronos_demo
        run_chronos_demo()

    elif args.command == "sim":
        from scripts.demo_attack_simulation import run_attack_simulation
        run_attack_simulation()

    elif args.command == "serve":
        print(f"[*] Launching CHRONOS-FL Investigation Dashboard on http://{args.host}:{args.port}")
        uvicorn.run("chronos.api.app:app", host=args.host, port=args.port, reload=True)

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
