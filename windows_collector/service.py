"""
Windows Telemetry Collector Service
Orchestrates Event Log, File Tail, and Network collectors.
Transmits batches to SOC backend API (/api/telemetry/ingest).
Exposes local REST control and health endpoints (/health, /status, /start, /stop, /collect-now).
"""
import sys
import time
import json
import socket
import logging
import threading
import urllib.request
import urllib.error
from http.server import HTTPServer, BaseHTTPRequestHandler
from typing import Dict, Any, List

from windows_collector.config import CollectorConfig
from windows_collector.normalizer import EventNormalizer, utc_now_iso
from windows_collector.collectors.event_log_collector import WindowsEventLogCollector
from windows_collector.collectors.file_tail_collector import AppFileTailCollector
from windows_collector.collectors.network_collector import NetworkTelemetryCollector

logger = logging.getLogger("WindowsCollectorService")

class WindowsCollectorService:
    def __init__(self, config: CollectorConfig):
        self.config = config
        self.is_running = False
        self.worker_thread: threading.Thread = None
        self.health_server: HTTPServer = None
        self.health_thread: threading.Thread = None

        # Statistics
        self.start_time = None
        self.cycles_completed = 0
        self.total_events_collected = 0
        self.total_events_transmitted = 0
        self.total_transmission_errors = 0
        self.last_transmission_status = None
        self.last_collection_time = None

        # Components
        self.normalizer = EventNormalizer(default_hostname=self.config.hostname)
        self.event_log_collector = WindowsEventLogCollector(
            normalizer=self.normalizer,
            channels=self.config.event_log_channels,
            max_batch_size=self.config.max_batch_size
        )
        self.file_tail_collector = AppFileTailCollector(
            normalizer=self.normalizer,
            directories=self.config.app_log_directories,
            extensions=self.config.app_log_extensions,
            max_batch_size=self.config.max_batch_size
        )
        self.network_collector = NetworkTelemetryCollector(
            normalizer=self.normalizer,
            max_batch_size=self.config.max_batch_size
        )

        # Optional MongoDB client
        self.mongo_client = None
        if self.config.mongodb_uri:
            try:
                from pymongo import MongoClient
                self.mongo_client = MongoClient(self.config.mongodb_uri, serverSelectionTimeoutMS=2000)
                logger.info("Direct MongoDB connection configured for Windows Collector.")
            except Exception as e:
                logger.warning(f"Failed to initialize direct MongoDB connection: {e}")

    def start(self, run_health_server: bool = True):
        """
        Starts the periodic telemetry collection loop and HTTP health server.
        """
        if self.is_running:
            logger.warning("Collector service is already running.")
            return

        self.is_running = True
        self.start_time = time.time()
        logger.info(f"Starting Windows Collector Service on {self.normalizer.hostname}...")
        logger.info(f"Target SOC Backend: {self.config.backend_api_url}/api/telemetry/ingest")
        logger.info(f"Interval: {self.config.collection_interval}s, Max Batch: {self.config.max_batch_size}")
        logger.info(f"Enabled Collectors: {', '.join(self.config.enabled_collectors)}")

        # Start background collection worker
        self.worker_thread = threading.Thread(target=self._collection_loop, daemon=True, name="CollectorLoop")
        self.worker_thread.start()

        # Start local health & control server if enabled
        if run_health_server and self.config.health_server_port > 0:
            self._start_health_server()

    def stop(self):
        """
        Stops collection loop and closes health server.
        """
        if not self.is_running:
            return
        logger.info("Stopping Windows Collector Service...")
        self.is_running = False
        if self.health_server:
            try:
                self.health_server.shutdown()
            except Exception:
                pass
        logger.info("Windows Collector Service stopped.")

    def run_single_cycle(self) -> Dict[str, Any]:
        """
        Executes one collection pass across all enabled collectors,
        deduplicates, and transmits to the backend API.
        """
        self.cycles_completed += 1
        cycle_start = time.time()
        self.last_collection_time = utc_now_iso()
        collected_batch: List[Dict[str, Any]] = []

        # 1. Windows Event Logs
        if "win_event_log" in self.config.enabled_collectors:
            try:
                evt_logs = self.event_log_collector.collect()
                collected_batch.extend(evt_logs)
            except Exception as e:
                logger.error(f"Error in WindowsEventLogCollector: {e}")

        # 2. Application Log Files
        if "app_files" in self.config.enabled_collectors:
            try:
                file_logs = self.file_tail_collector.collect()
                collected_batch.extend(file_logs)
            except Exception as e:
                logger.error(f"Error in AppFileTailCollector: {e}")

        # 3. Network Telemetry
        if "network" in self.config.enabled_collectors:
            try:
                net_logs = self.network_collector.collect()
                collected_batch.extend(net_logs)
            except Exception as e:
                logger.error(f"Error in NetworkTelemetryCollector: {e}")

        self.total_events_collected += len(collected_batch)
        duration_ms = round((time.time() - cycle_start) * 1000, 2)

        # Transmit to Backend API if events exist
        transmission_result = None
        if collected_batch:
            transmission_result = self._transmit_events(collected_batch)

        return {
            "cycle": self.cycles_completed,
            "timestamp": self.last_collection_time,
            "events_collected": len(collected_batch),
            "duration_ms": duration_ms,
            "transmission": transmission_result
        }

    def _collection_loop(self):
        """
        Internal periodic worker loop.
        """
        while self.is_running:
            try:
                self.run_single_cycle()
            except Exception as e:
                logger.error(f"Unexpected error during collection cycle: {e}")

            # Sleep in small increments for responsive stop()
            slept = 0.0
            target_sleep = self.config.collection_interval
            while self.is_running and slept < target_sleep:
                time.sleep(0.5)
                slept += 0.5

    def _transmit_events(self, events: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Sends structured events to the existing Node.js SOC Backend: POST /api/telemetry/ingest
        """
        target_url = f"{self.config.backend_api_url}/api/telemetry/ingest"
        payload = {
            "source": "system",
            "isSimulated": False,  # Strictly real telemetry
            "host": self.normalizer.hostname,
            "structuredEvents": events
        }

        # Optional direct MongoDB persistence
        if self.mongo_client:
            try:
                db = self.mongo_client[self.config.mongodb_db_name]
                db.raw_events.insert_many(events, ordered=False)
            except Exception as me:
                logger.debug(f"Direct MongoDB insert note: {me}")

        try:
            req_data = json.dumps(payload).encode("utf-8")
            headers = {
                "Content-Type": "application/json",
                "User-Agent": "WindowsTelemetryCollector/1.0"
            }
            if self.config.backend_api_key:
                headers["Authorization"] = f"Bearer {self.config.backend_api_key}"

            req = urllib.request.Request(target_url, data=req_data, headers=headers)
            with urllib.request.urlopen(req, timeout=8.0) as resp:
                status_code = resp.getcode()
                resp_body = resp.read().decode("utf-8")
                parsed_resp = json.loads(resp_body) if resp_body else {}

                self.total_events_transmitted += len(events)
                self.last_transmission_status = {
                    "success": True,
                    "http_status": status_code,
                    "backend_response": parsed_resp,
                    "timestamp": utc_now_iso()
                }
                logger.info(f"Successfully transmitted {len(events)} events to SOC backend (HTTP {status_code}).")
                return self.last_transmission_status
        except urllib.error.HTTPError as he:
            self.total_transmission_errors += 1
            err_text = he.read().decode("utf-8", errors="replace")
            self.last_transmission_status = {
                "success": False,
                "http_status": he.code,
                "error": err_text,
                "timestamp": utc_now_iso()
            }
            logger.warning(f"Backend rejected telemetry (HTTP {he.code}): {err_text}")
            return self.last_transmission_status
        except Exception as e:
            self.total_transmission_errors += 1
            self.last_transmission_status = {
                "success": False,
                "error": str(e),
                "timestamp": utc_now_iso()
            }
            logger.warning(f"Failed to transmit telemetry to {target_url}: {e}")
            return self.last_transmission_status

    def get_health(self) -> Dict[str, Any]:
        uptime_sec = round(time.time() - self.start_time, 1) if self.start_time else 0
        return {
            "status": "HEALTHY" if self.is_running else "STOPPED",
            "service": "Windows Security Telemetry Collector",
            "version": "1.0.0",
            "hostname": self.normalizer.hostname,
            "uptime_seconds": uptime_sec,
            "is_running": self.is_running,
            "cycles_completed": self.cycles_completed,
            "total_events_collected": self.total_events_collected,
            "total_events_transmitted": self.total_events_transmitted,
            "total_transmission_errors": self.total_transmission_errors,
            "last_collection_time": self.last_collection_time,
            "last_transmission": self.last_transmission_status,
            "deduplication": self.normalizer.deduplicator.get_stats()
        }

    def get_detailed_status(self) -> Dict[str, Any]:
        health = self.get_health()
        health.update({
            "configuration": self.config.to_dict(),
            "collectors": {
                "windows_event_log": self.event_log_collector.get_status(),
                "application_file_tail": self.file_tail_collector.get_status(),
                "network_telemetry": self.network_collector.get_status()
            }
        })
        return health

    def _start_health_server(self):
        """
        Spawns lightweight HTTP server for status and control.
        """
        service_ref = self

        class HealthRequestHandler(BaseHTTPRequestHandler):
            def log_message(self, format, *args):
                pass  # Suppress default noisy access logs

            def do_GET(self):
                if self.path == "/health":
                    self._send_json(200, service_ref.get_health())
                elif self.path == "/status":
                    self._send_json(200, service_ref.get_detailed_status())
                else:
                    self._send_json(404, {"error": "Not Found", "endpoints": ["/health", "/status", "/start", "/stop", "/collect-now"]})

            def do_POST(self):
                if self.path == "/start":
                    if not service_ref.is_running:
                        service_ref.is_running = True
                        service_ref.worker_thread = threading.Thread(target=service_ref._collection_loop, daemon=True)
                        service_ref.worker_thread.start()
                    self._send_json(200, {"success": True, "message": "Collector started", "status": service_ref.get_health()})
                elif self.path == "/stop":
                    service_ref.is_running = False
                    self._send_json(200, {"success": True, "message": "Collector paused", "status": service_ref.get_health()})
                elif self.path == "/collect-now":
                    res = service_ref.run_single_cycle()
                    self._send_json(200, {"success": True, "result": res, "status": service_ref.get_health()})
                else:
                    self._send_json(404, {"error": "Not Found"})

            def _send_json(self, status: int, data: Any):
                body = json.dumps(data, indent=2).encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Access-Control-Allow-Origin", "*")
                self.end_headers()
                self.wfile.write(body)

        try:
            self.health_server = HTTPServer(("0.0.0.0", self.config.health_server_port), HealthRequestHandler)
            self.health_thread = threading.Thread(target=self.health_server.serve_forever, daemon=True, name="HealthServer")
            self.health_thread.start()
            logger.info(f"Collector health server listening at http://127.0.0.1:{self.config.health_server_port}")
        except Exception as e:
            logger.warning(f"Could not bind collector health server on port {self.config.health_server_port}: {e}")
