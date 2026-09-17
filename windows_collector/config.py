"""
Windows Telemetry Collector Configuration
Loads settings from environment variables and CLI overrides.
"""
import os
from typing import List

class CollectorConfig:
    def __init__(
        self,
        enabled_collectors: List[str] = None,
        event_log_channels: List[str] = None,
        app_log_directories: List[str] = None,
        app_log_extensions: List[str] = None,
        collection_interval: float = 5.0,
        max_batch_size: int = 50,
        backend_api_url: str = "http://127.0.0.1:3000",
        backend_api_key: str = "",
        mongodb_uri: str = "",
        mongodb_db_name: str = "cyber_defense_db",
        health_server_port: int = 8085,
        log_level: str = "INFO",
        hostname: str = None
    ):
        self.enabled_collectors = enabled_collectors or ["win_event_log", "app_files", "network"]
        self.event_log_channels = event_log_channels or ["System", "Application", "Security"]
        self.app_log_directories = app_log_directories or [r"C:\inetpub\logs", r"C:\ProgramData\AppLogs", "logs"]
        self.app_log_extensions = app_log_extensions or [".log", ".txt", ".json", ".jsonl"]
        self.collection_interval = max(0.5, float(collection_interval))
        self.max_batch_size = max(1, int(max_batch_size))
        self.backend_api_url = backend_api_url.rstrip("/")
        self.backend_api_key = backend_api_key
        self.mongodb_uri = mongodb_uri
        self.mongodb_db_name = mongodb_db_name
        self.health_server_port = int(health_server_port)
        self.log_level = log_level.upper()
        self.hostname = hostname

    @classmethod
    def from_env(cls) -> "CollectorConfig":
        enabled_str = os.getenv("ENABLED_COLLECTORS", "win_event_log,app_files,network")
        enabled = [x.strip() for x in enabled_str.split(",") if x.strip()]

        channels_str = os.getenv("WIN_EVENT_CHANNELS", "System,Application,Security")
        channels = [x.strip() for x in channels_str.split(",") if x.strip()]

        dirs_str = os.getenv("APP_LOG_DIRECTORIES", r"C:\inetpub\logs,C:\ProgramData\AppLogs,logs")
        dirs = [x.strip() for x in dirs_str.split(",") if x.strip()]

        exts_str = os.getenv("APP_LOG_EXTENSIONS", ".log,.txt,.json,.jsonl")
        exts = [x.strip() for x in exts_str.split(",") if x.strip()]

        interval = float(os.getenv("COLLECTION_INTERVAL_SEC", os.getenv("COLLECTION_INTERVAL", "5.0")))
        batch_size = int(os.getenv("MAX_BATCH_SIZE", "50"))
        api_url = os.getenv("BACKEND_API_URL", "http://127.0.0.1:3000")
        api_key = os.getenv("BACKEND_API_KEY", "")
        mongo_uri = os.getenv("MONGODB_URI", "")
        mongo_db = os.getenv("MONGODB_DB_NAME", "cyber_defense_db")
        health_port = int(os.getenv("COLLECTOR_HEALTH_PORT", "8085"))
        log_level = os.getenv("LOG_LEVEL", "INFO")

        return cls(
            enabled_collectors=enabled,
            event_log_channels=channels,
            app_log_directories=dirs,
            app_log_extensions=exts,
            collection_interval=interval,
            max_batch_size=batch_size,
            backend_api_url=api_url,
            backend_api_key=api_key,
            mongodb_uri=mongo_uri,
            mongodb_db_name=mongo_db,
            health_server_port=health_port,
            log_level=log_level
        )

    def to_dict(self) -> dict:
        return {
            "enabled_collectors": self.enabled_collectors,
            "event_log_channels": self.event_log_channels,
            "app_log_directories": self.app_log_directories,
            "app_log_extensions": self.app_log_extensions,
            "collection_interval": self.collection_interval,
            "max_batch_size": self.max_batch_size,
            "backend_api_url": self.backend_api_url,
            "has_backend_api_key": bool(self.backend_api_key),
            "has_mongodb_uri": bool(self.mongodb_uri),
            "health_server_port": self.health_server_port,
            "log_level": self.log_level
        }
