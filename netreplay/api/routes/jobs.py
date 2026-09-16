"""Async job/status endpoints (#49): workspace summary + job registry."""
from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, HTTPException, Request

import netreplay
from netreplay.api.schemas import JobOut, WorkspaceOut
from netreplay.core.jobs import (
    Job,
    JobManager,
    job_manager,
)
from netreplay.core.service import NetReplayService

router = APIRouter(tags=["jobs"])


def _job_out(job: Job) -> JobOut:
    return JobOut(
        id=job.job_id,
        kind=job.kind,
        status=job.status.value,
        progress=job.progress,
        parameters=dict(job.parameters),
        created_at=job.created_at,
        started_at=job.started_at,
        finished_at=job.finished_at,
        result=job.result,
        error=job.error,
    )


def _manager(request: Request) -> JobManager:
    return job_manager()


@router.get("/jobs", response_model=list[JobOut])
def list_jobs(
    request: Request,
    kind: str | None = None,
    status: str | None = None,
) -> list[JobOut]:
    return [_job_out(j) for j in _manager(request).list(kind=kind, status=status)]


@router.get("/jobs/{job_id}", response_model=JobOut)
def get_job(request: Request, job_id: str) -> JobOut:
    job = _manager(request).get(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail=f"job not found: {job_id}")
    return _job_out(job)


@router.post("/jobs/{job_id}/cancel", response_model=JobOut)
def cancel_job(request: Request, job_id: str) -> JobOut:
    job = _manager(request).cancel(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail=f"job not found: {job_id}")
    return _job_out(job)


@router.get("/workspace", response_model=WorkspaceOut)
def workspace_info(request: Request) -> WorkspaceOut:
    service: NetReplayService = request.app.state.service
    return WorkspaceOut(
        path=str(service.workspace),
        name=Path(service.workspace).name,
        version=netreplay.__version__,
        session_count=len(service.list_sessions()),
    )
