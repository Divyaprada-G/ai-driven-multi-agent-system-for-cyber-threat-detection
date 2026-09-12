"""
AI DRIVEN MULTI-AGENT SYSTEM FOR CYBER THREAT DETECTION
Local Live Security Event Simulator
Prompt 12 — Safe Synthetic Cybersecurity Event Generation
Label: SIMULATED SECURITY EVENT (Zero Destructive Actions)
"""

import time
import random
import threading
from typing import Dict, Any, Optional

class LiveEventSimulator:
    def __init__(self, pipeline):
        self.pipeline = pipeline
        self.is_running = False
        self.event_rate = 2 # events per second
        self.mode = "mixed" # mixed, normal, suspicious, multistage
        self._thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()

    def start(self, event_rate: int = 2, mode: str = "mixed"):
        with self._lock:
            self.event_rate = max(1, min(10, event_rate))
            self.mode = mode
            if not self.is_running:
                self.is_running = True
                self._thread = threading.Thread(target=self._run_loop, daemon=True)
                self._thread.start()

    def stop(self):
        with self._lock:
            self.is_running = False

    def _run_loop(self):
        stage_counter = 0
        while self.is_running:
            delay = 1.0 / self.event_rate
            time.sleep(delay)

            if not self.is_running:
                break

            # Generate synthetic event
            event = self._generate_synthetic_event(stage_counter)
            stage_counter = (stage_counter + 1) % 10
            
            # Enqueue into the live pipeline
            self.pipeline.enqueue_event(event)

    def _generate_synthetic_event(self, step: int) -> Dict[str, Any]:
        """
        Generates structured synthetic event with CICIDS2017/UNSW style features.
        Clearly marked with isSimulated=True.
        """
        # Determine if this event should be normal or suspicious based on mode
        is_suspicious = False
        if self.mode == "suspicious":
            is_suspicious = True
        elif self.mode == "normal":
            is_suspicious = False
        elif self.mode == "multistage":
            # Steps 3, 4, 5 represent attack progression
            is_suspicious = step in [2, 3, 4, 5]
        else: # mixed
            is_suspicious = random.random() < 0.45

        # Choose event category: network, system, application
        categories = ["network", "system", "application"]
        category = random.choice(categories)

        if category == "network":
            if is_suspicious:
                event_type = random.choice(["PortScan Probe", "DDoS SYN Flood", "Infiltration Ingress", "Abnormal Flow Burst"])
                features = {
                    "Flow Duration": random.randint(1000000, 15000000),
                    "Total Fwd Packets": random.randint(50, 600),
                    "Total Backward Packets": random.randint(0, 10),
                    "Total Length of Fwd Packets": random.randint(2000, 50000),
                    "Total Length of Bwd Packets": random.randint(0, 200),
                    "Flow Bytes/s": round(random.uniform(50000.0, 500000.0), 2),
                    "Flow Packets/s": round(random.uniform(200.0, 1500.0), 2),
                    "Flow IAT Mean": round(random.uniform(10.0, 50.0), 2),
                    "SYN Flag Count": random.randint(10, 50),
                    "FIN Flag Count": 0,
                    "RST Flag Count": random.randint(0, 5),
                    "ACK Flag Count": 1
                }
                src_ip = f"198.51.100.{random.randint(2, 250)}"
                dst_ip = "172.16.0.10"
                dst_port = random.choice([22, 80, 443, 8080, 4444])
            else:
                event_type = "Standard Web Traffic (HTTPS)"
                features = {
                    "Flow Duration": random.randint(20000, 250000),
                    "Total Fwd Packets": random.randint(5, 25),
                    "Total Backward Packets": random.randint(6, 30),
                    "Total Length of Fwd Packets": random.randint(500, 3000),
                    "Total Length of Bwd Packets": random.randint(1500, 15000),
                    "Flow Bytes/s": round(random.uniform(1000.0, 8000.0), 2),
                    "Flow Packets/s": round(random.uniform(10.0, 50.0), 2),
                    "Flow IAT Mean": round(random.uniform(200.0, 800.0), 2),
                    "SYN Flag Count": 1,
                    "FIN Flag Count": 1,
                    "RST Flag Count": 0,
                    "ACK Flag Count": 15
                }
                src_ip = f"192.168.1.{random.randint(10, 200)}"
                dst_ip = "172.16.0.5"
                dst_port = 443

        elif category == "system":
            if is_suspicious:
                event_type = random.choice(["Repeated Authentication Failure (SSH)", "Privilege Escalation sudo attempt", "Suspicious PowerShell Spawn", "Sensitive File Read /etc/shadow"])
                features = {
                    "Flow Duration": 150000,
                    "Total Fwd Packets": 12,
                    "Total Backward Packets": 4,
                    "Total Length of Fwd Packets": 1200,
                    "Total Length of Bwd Packets": 300,
                    "Flow Bytes/s": 4500.0,
                    "Flow Packets/s": 40.0,
                    "failedLoginsCount": random.randint(5, 25),
                    "privilegeEscalationsCount": 1,
                    "lateralMovementAttempts": 0
                }
                src_ip = "192.168.1.150"
                dst_ip = "172.16.0.2"
                dst_port = 22
            else:
                event_type = "Normal System Service Heartbeat"
                features = {
                    "Flow Duration": 5000,
                    "Total Fwd Packets": 2,
                    "Total Backward Packets": 2,
                    "Total Length of Fwd Packets": 120,
                    "Total Length of Bwd Packets": 120,
                    "Flow Bytes/s": 500.0,
                    "Flow Packets/s": 5.0,
                    "failedLoginsCount": 0,
                    "privilegeEscalationsCount": 0
                }
                src_ip = "127.0.0.1"
                dst_ip = "127.0.0.1"
                dst_port = 9100

        else: # application
            if is_suspicious:
                event_type = random.choice(["SQL Injection attempt ' OR 1=1--", "Directory Traversal ../../etc/passwd", "Cross-Site Scripting <script>", "Brute Force Login Burst"])
                features = {
                    "Flow Duration": 450000,
                    "Total Fwd Packets": 45,
                    "Total Backward Packets": 40,
                    "Total Length of Fwd Packets": 15000,
                    "Total Length of Bwd Packets": 25000,
                    "Flow Bytes/s": 25000.0,
                    "Flow Packets/s": 120.0,
                    "payloadRiskKeywords": 3,
                    "httpStatus": 403
                }
                src_ip = f"203.0.113.{random.randint(10, 100)}"
                dst_ip = "172.16.0.80"
                dst_port = 8080
            else:
                event_type = "API GET /api/v1/health Normal Query"
                features = {
                    "Flow Duration": 12000,
                    "Total Fwd Packets": 3,
                    "Total Backward Packets": 3,
                    "Total Length of Fwd Packets": 240,
                    "Total Length of Bwd Packets": 512,
                    "Flow Bytes/s": 1200.0,
                    "Flow Packets/s": 15.0,
                    "payloadRiskKeywords": 0,
                    "httpStatus": 200
                }
                src_ip = "192.168.1.55"
                dst_ip = "172.16.0.80"
                dst_port = 8080

        return {
            "eventId": f"SIM-EVT-{int(time.time()*1000)%1000000}",
            "source": category,
            "eventType": f"[SIMULATED] {event_type}",
            "sourceIp": src_ip,
            "destinationIp": dst_ip,
            "sourcePort": random.randint(1024, 65535),
            "destinationPort": dst_port,
            "protocol": "TCP",
            "features": features,
            "isSimulated": True,
            "details": f"SIMULATED SECURITY EVENT generated by built-in local simulator for pipeline validation. Zero real network damage."
        }
