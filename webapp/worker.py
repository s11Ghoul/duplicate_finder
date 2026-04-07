"""Background worker thread for processing scan jobs sequentially."""

import queue
import threading

from webapp.models import ScanJob
from webapp.scanner import ScanOrchestrator
from webapp.vpn import VPNManager


class JobQueue:
    """Single-threaded job queue. Only one scan runs at a time (VPN is system-wide)."""

    def __init__(self):
        self._queue: queue.Queue[ScanJob] = queue.Queue()
        self._jobs: dict[str, ScanJob] = {}
        self._worker = threading.Thread(target=self._process, daemon=True)
        self._current_job: ScanJob | None = None

    def start(self):
        self._worker.start()

    def enqueue(self, job: ScanJob):
        job.captcha_event = threading.Event()
        self._jobs[job.id] = job
        self._queue.put(job)

    def get_job(self, job_id: str) -> ScanJob | None:
        return self._jobs.get(job_id)

    def get_all_jobs(self) -> list[ScanJob]:
        return list(reversed(self._jobs.values()))

    @property
    def current_job(self) -> ScanJob | None:
        return self._current_job

    def _process(self):
        vpn = VPNManager()
        while True:
            job = self._queue.get()
            self._current_job = job
            try:
                orchestrator = ScanOrchestrator(vpn=vpn)
                orchestrator.run_job(job)
            except Exception as e:
                if job.status != "failed":
                    job.status = "failed"
                    job.error = str(e)
                    job.add_log(f"Worker error: {e}")
            finally:
                self._current_job = None
                self._queue.task_done()
