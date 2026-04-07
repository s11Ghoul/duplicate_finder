from dataclasses import dataclass, field
from datetime import datetime
import uuid


@dataclass
class ScanJob:
    brands: list[str]
    countries: list[str]
    id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    status: str = "queued"  # queued | running | paused_captcha | completed | failed
    created_at: datetime = field(default_factory=datetime.now)
    started_at: datetime | None = None
    completed_at: datetime | None = None
    progress: dict = field(default_factory=lambda: {
        "current_brand": None,
        "current_country": None,
        "current_query": None,
        "brands_done": 0,
        "brands_total": 0,
        "queries_done": 0,
        "queries_total": 0,
        "sites_checked": 0,
        "suspicious_found": 0,
    })
    result_files: dict[str, str] = field(default_factory=dict)
    log: list[str] = field(default_factory=list)
    captcha_pending: bool = False
    captcha_event: object = None  # threading.Event, set from outside
    error: str | None = None

    def add_log(self, message: str):
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.log.append(f"[{timestamp}] {message}")

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "brands": self.brands,
            "countries": self.countries,
            "status": self.status,
            "created_at": self.created_at.isoformat(),
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "progress": self.progress,
            "result_files": list(self.result_files.keys()),
            "captcha_pending": self.captcha_pending,
            "error": self.error,
            "log_count": len(self.log),
        }
