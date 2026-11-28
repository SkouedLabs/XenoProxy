"""Background worker.

Each submitted job becomes one `run_job` task. Inside that task the job runs its
three phases in order — analyzers, then connectors, then pivots — with the
analyzers concurrent, so a job's parallelism stays bounded and observable.

The task hands the orchestrator two things it cannot reach on its own: the queue
client, used to poll for a cancellation request and to enqueue the child jobs a
pivot creates.
"""

from __future__ import annotations

import uuid
from collections.abc import Callable
from typing import Any, ClassVar

from arq.connections import RedisSettings

from app.core import http_client
from app.core.config import get_settings
from app.core.db import dispose_engine, get_session_factory
from app.core.logging import configure_logging, get_logger
from app.core.sandbox import install_exec_guard
from app.plugins import load_all
from app.services import app_settings, orchestrator, yara_rules

logger = get_logger(__name__)


async def run_job(context: dict[str, Any], job_id: str) -> None:
    """Entry point enqueued by the API for every submitted job."""
    queue = context.get("redis")
    await _refresh_outbound_route()

    async def enqueue(child_id: uuid.UUID) -> None:
        """Schedule a child job a pivot created."""
        if queue is None:
            logger.warning("pivot_child_not_enqueued", job_id=str(child_id))
            return
        await queue.enqueue_job("run_job", str(child_id))

    await orchestrator.run_job(
        get_session_factory(),
        uuid.UUID(job_id),
        store=queue,
        enqueue=enqueue,
    )


async def pull_yara_ruleset(_context: dict[str, Any], source_id: str) -> None:
    """Download a public YARA ruleset. Only the worker has an outbound route."""
    await _refresh_outbound_route()
    yara_rules.write_status(source=source_id, state="running")
    try:
        meta = await yara_rules.pull(source_id)
    except yara_rules.PullError as exc:
        yara_rules.write_status(source=source_id, state="failed", error=str(exc))
        logger.warning("yara_pull_failed", source=source_id, error=str(exc))
        return
    except Exception as exc:
        yara_rules.write_status(
            source=source_id, state="failed", error=f"Unexpected error: {type(exc).__name__}"
        )
        logger.exception("yara_pull_crashed", source=source_id)
        return
    yara_rules.write_status(
        source=source_id, state="done", files=meta["files"], compiled=meta["compiled"]
    )


async def _refresh_outbound_route() -> None:
    """Pick up the outbound route an administrator may have changed.

    The analyzers run here, so a proxy or a certificate authority saved in the
    interface has to reach this process. One row per job is cheap next to the
    provider calls the job is about to make.
    """
    factory = get_session_factory()
    async with factory() as session:
        http_client.set_network(await app_settings.reload(session, "network"))


async def startup(_context: dict[str, Any]) -> None:
    settings = get_settings()
    configure_logging(settings.log_level)
    install_exec_guard()
    plugins = load_all()
    await _refresh_outbound_route()
    logger.info("worker_started", plugins=len(plugins))


async def shutdown(_context: dict[str, Any]) -> None:
    await dispose_engine()


def _redis_settings() -> RedisSettings:
    settings = get_settings()
    return RedisSettings(
        host=settings.redis_host,
        port=settings.redis_port,
        database=settings.redis_db,
        password=settings.redis_password or None,
    )


class WorkerSettings:
    """arq worker definition, referenced as `app.worker.WorkerSettings`."""

    functions: ClassVar[list[Callable[..., Any]]] = [run_job, pull_yara_ruleset]
    on_startup = startup
    on_shutdown = shutdown
    max_jobs = 20
    job_timeout = 900
    keep_result = 3600
    redis_settings = _redis_settings()
