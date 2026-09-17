#!/usr/bin/env python3
"""
AI-Driven Multi-Agent Cyber Threat Detection
Windows Security & Application Telemetry Collector CLI
Collects genuine security telemetry from Windows Event Logs, Application log files,
and Network socket tables, and streams to the SOC backend.
"""
import sys
import os
import signal
import argparse
import logging

from windows_collector.config import CollectorConfig
from windows_collector.service import WindowsCollectorService

def setup_logging(level_str: str):
    numeric_level = getattr(logging, level_str.upper(), logging.INFO)
    logging.basicConfig(
        level=numeric_level,
        format="%(asctime)s [%(levelname)s] [%(name)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )

def main():
    parser = argparse.ArgumentParser(
        description="AI-Driven Multi-Agent Cyber Threat Detection: Windows Telemetry Collector"
    )
    parser.add_argument(
        "--server",
        default=os.getenv("BACKEND_API_URL", "http://127.0.0.1:3000"),
        help="Target SOC Backend URL (default: http://127.0.0.1:3000)"
    )
    parser.add_argument(
        "--interval",
        type=float,
        default=float(os.getenv("COLLECTION_INTERVAL_SEC", "5.0")),
        help="Polling interval in seconds (default: 5.0)"
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=int(os.getenv("MAX_BATCH_SIZE", "50")),
        help="Maximum events per batch (default: 50)"
    )
    parser.add_argument(
        "--channels",
        default=os.getenv("WIN_EVENT_CHANNELS", "System,Application,Security"),
        help="Comma-separated Windows Event Log channels (default: System,Application,Security)"
    )
    parser.add_argument(
        "--app-dirs",
        default=os.getenv("APP_LOG_DIRECTORIES", r"C:\inetpub\logs,C:\ProgramData\AppLogs,logs"),
        help="Comma-separated directories to tail for application logs"
    )
    parser.add_argument(
        "--collectors",
        default=os.getenv("ENABLED_COLLECTORS", "win_event_log,app_files,network"),
        help="Comma-separated list of enabled collectors (win_event_log,app_files,network)"
    )
    parser.add_argument(
        "--health-port",
        type=int,
        default=int(os.getenv("COLLECTOR_HEALTH_PORT", "8085")),
        help="Port for local collector health & control server (default: 8085)"
    )
    parser.add_argument(
        "--log-level",
        default=os.getenv("LOG_LEVEL", "INFO"),
        help="Log verbosity: DEBUG, INFO, WARNING, ERROR"
    )
    parser.add_argument(
        "--once",
        action="store_true",
        help="Execute a single collection cycle and exit"
    )

    args = parser.parse_args()
    setup_logging(args.log_level)
    logger = logging.getLogger("WindowsCollector")

    channels = [c.strip() for c in args.channels.split(",") if c.strip()]
    app_dirs = [d.strip() for d in args.app_dirs.split(",") if d.strip()]
    collectors = [c.strip() for c in args.collectors.split(",") if c.strip()]

    config = CollectorConfig(
        enabled_collectors=collectors,
        event_log_channels=channels,
        app_log_directories=app_dirs,
        collection_interval=args.interval,
        max_batch_size=args.batch_size,
        backend_api_url=args.server,
        health_server_port=args.health_port,
        log_level=args.log_level
    )

    service = WindowsCollectorService(config)

    # If --once requested, run single cycle and exit
    if args.once:
        logger.info("Executing single collection cycle (--once)...")
        res = service.run_single_cycle()
        print(f"Cycle completed: {res['events_collected']} events collected in {res['duration_ms']}ms.")
        if res.get("transmission"):
            print(f"Transmission result: {res['transmission'].get('http_status')} (Success: {res['transmission'].get('success')})")
        sys.exit(0)

    # Signal handlers
    def handle_shutdown(signum, frame):
        logger.info("Shutdown signal received. Terminating collector gracefully...")
        service.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, handle_shutdown)
    signal.signal(signal.SIGTERM, handle_shutdown)

    # Start service
    service.start(run_health_server=True)

    print("=================================================================")
    print("  WINDOWS REAL TELEMETRY COLLECTOR SERVICE IS ACTIVE")
    print("=================================================================")
    print(f"  Hostname:           {service.normalizer.hostname}")
    print(f"  Target SOC Server:  {config.backend_api_url}/api/telemetry/ingest")
    print(f"  Health Endpoint:    http://127.0.0.1:{config.health_server_port}/health")
    print(f"  Status Endpoint:    http://127.0.0.1:{config.health_server_port}/status")
    print(f"  Interval:           {config.collection_interval}s")
    print(f"  Collectors:         {', '.join(config.enabled_collectors)}")
    print(f"  Event Channels:     {', '.join(config.event_log_channels)}")
    print(f"  Application Dirs:   {', '.join(config.app_log_directories)}")
    print("=================================================================\n")

    # Main thread keep-alive
    try:
        while service.is_running:
            import time
            time.sleep(1.0)
    except KeyboardInterrupt:
        handle_shutdown(None, None)

if __name__ == "__main__":
    main()
