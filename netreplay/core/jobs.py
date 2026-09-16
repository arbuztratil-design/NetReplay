"""Background job registry (#49): workspace/session/flow/packet/replay + async jobs."""
from __future__ import annotations

import threading
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from enum import Enum


class JobStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    CANCELLED = "cancelled"


_TERMINAL = frozenset({JobStatus.SUCCEEDED, JobStatus.FAILED, JobStatus.CANCELLED})


def _now() -> float:
    return time.time()


@dataclass(slots=True)
class Job:
    kind: str
    parameters: dict
    job_id: str = ""
    status: JobStatus = JobStatus.PENDING
    progress: float = 0.0
    created_at: float = 0.0
    started_at: float | None = None
    finished_at: float | None = None
    result: dict | None = None
    error: str | None = None
    _cancel: bool = False
    _cancel_lock: threading.Lock = threading.Lock()

    def __post_init__(self) -> None:
        if not self.job_id:
            self.job_id = uuid.uuid4().hex
        if self.created_at == 0.0:
            self.created_at = _now()

    @property
    def done(self) -> bool:
        return self.status in _TERMINAL

    @property
    def cancel_requested(self) -> bool:
        return self._cancel

    def request_cancel(self) -> None:
        with self._cancel_lock:
            self._cancel = True
            if self.done:
                return
            if self.status is JobStatus.PENDING:
                self.status = JobStatus.CANCELLED
                self.finished_at = _now()


JobFunc = Callable[[Job], dict | None]


@dataclass(slots=True)
class _Entry:
    job: Job
    thread: threading.Thread | None = None


class JobManager:
    """Thread-safe async job registry (#49)."""

    def __init__(self) -> None:
        self._entries: dict[str, _Entry] = {}
        self._lock = threading.RLock()

    def submit(self, kind: str, func: JobFunc, **parameters: object) -> Job:
        job = Job(kind=kind, parameters=dict(parameters), job_id=uuid.uuid4().hex)
        thread = threading.Thread(
            target=self._run, args=(job, func),
            name=f"netreplay-job-{job.job_id[:8]}", daemon=True,
        )
        with self._lock:
            self._entries[job.job_id] = _Entry(job=job, thread=thread)
        thread.start()
        return job

    def _run(self, job: Job, func: JobFunc) -> None:
        while True:
            if job.cancel_requested:
                job.request_cancel()
                return
            with self._lock:
                if job.status is not JobStatus.PENDING:
                    break
                job.status = JobStatus.RUNNING
                job.started_at = _now()
        try:
            result = func(job)
        except Exception as exc:  # noqa: BLE001 - reported on the job
            with self._lock:
                job.error = f"{type(exc).__name__}: {exc}"
                job.status = JobStatus.FAILED
        else:
            with self._lock:
                job.result = result or {}
                job.status = JobStatus.SUCCEEDED
        finally:
            with self._lock:
                job.finished_at = _now()

    def get(self, job_id: str) -> Job | None:
        with self._lock:
            entry = self._entries.get(job_id)
            return entry.job if entry else None

    def list(self, *, kind: str | None = None, status: str | None = None) -> list[Job]:
        with self._lock:
            jobs = [e.job for e in self._entries.values()]
        if kind:
            jobs = [j for j in jobs if j.kind == kind]
        if status:
            jobs = [j for j in jobs if j.status.value == status]
        return sorted(jobs, key=lambda j: (j.created_at, j.job_id))

    def cancel(self, job_id: str) -> Job | None:
        with self._lock:
            entry = self._entries.get(job_id)
            if entry is None:
                return None
            entry.job.request_cancel()
            return entry.job


_job_manager: JobManager | None = None


def job_manager() -> JobManager:
    """Process-wide job manager singleton (lazily created)."""
    global _job_manager
    if _job_manager is None:
        _job_manager = JobManager()
    return _job_manager
