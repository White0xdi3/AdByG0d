"""
AdByG0d — Celery application bootstrap.

The Celery app is created here and imported by tasks/workers.  Import this
module to get a fully configured Celery instance; do not create secondary
Celery() objects elsewhere.

Broker and result backend are configured via CELERY_BROKER_URL and
CELERY_RESULT_BACKEND in settings (see config.py / .env.example).
Default: Redis DB 1 (separate from pub/sub on DB 0).

To start a Celery worker locally::

    cd apps/api
    PYTHONPATH=src celery -A adbygod_api.core.celery_app:celery_app worker \
        --loglevel=info --queues=offensive_jobs

For development without Redis, the eager (inline) mode can be enabled::

    CELERY_TASK_ALWAYS_EAGER=true  # executes tasks synchronously in the API
    CELERY_TASK_EAGER_PROPAGATES=true

See docs/architecture.md for production deployment guidance and the roadmap
for switching to RabbitMQ if queue durability requirements grow.
"""

from __future__ import annotations

from celery import Celery


def _make_celery() -> Celery:
    from adbygod_api.config import settings  # late import: avoids import-time circular deps

    app = Celery("adbygod")
    app.config_from_object(
        {
            "broker_url": settings.CELERY_BROKER_URL,
            "result_backend": settings.CELERY_RESULT_BACKEND,
            "task_serializer": "json",
            "result_serializer": "json",
            "accept_content": ["json"],
            # Acknowledge only after the task completes, so a worker crash
            # causes the broker to redeliver the task.
            "task_acks_late": True,
            "task_reject_on_worker_lost": True,
            # One task per worker at a time — offensive jobs are I/O-bound and
            # spawning many concurrent subprocesses on one host is undesirable.
            "worker_prefetch_multiplier": 1,
            # Discover tasks from the tasks package.
            "imports": [
                "adbygod_api.core.tasks.offensive_jobs",
                "adbygod_api.core.tasks.graph_projection",
                "adbygod_api.core.recon.recon_engine",
            ],
        }
    )
    return app


celery_app = _make_celery()
