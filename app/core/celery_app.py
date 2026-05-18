"""
app/core/celery_app.py
───────────────────────
Celery application instance for background scan tasks.
Workers are started separately:  celery -A app.core.celery_app worker -l info
"""

from celery import Celery

from app.core.config import settings

celery_app = Celery(
    "smartfuzz",
    broker=settings.CELERY_BROKER_URL,
    backend=settings.CELERY_RESULT_BACKEND,
    include=[
        "app.services.fuzzer.tasks",  # fuzzing background tasks
        "app.services.crawler.tasks",  # crawler background tasks
    ],
)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_acks_late=True,  # tasks acknowledged after completion
    worker_prefetch_multiplier=1,  # one task at a time per worker
    task_routes={
        "app.services.fuzzer.tasks.*": {"queue": "fuzzing"},
        "app.services.crawler.tasks.*": {"queue": "crawling"},
    },
    beat_schedule={},
)
