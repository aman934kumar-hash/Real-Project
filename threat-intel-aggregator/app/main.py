"""
FastAPI application factory and lifespan handler.
"""
import logging
import logging.config
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.config import get_settings
from app.routes import alerts, enrichment, feeds, iocs

settings = get_settings()

# ──────────────────────────── Logging ────────────────────────────────────────

logging.basicConfig(
    level=logging.DEBUG if settings.debug else logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(name)s — %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
logger = logging.getLogger(__name__)


# ──────────────────────────── Lifespan ───────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup → yield → shutdown."""
    logger.info("Starting %s v%s", settings.app_name, settings.app_version)

    # Start background scheduler
    if settings.scheduler_enabled:
        from app.scheduler import setup_scheduler
        scheduler = setup_scheduler()
        scheduler.start()
        logger.info("APScheduler started.")

    yield

    # Shutdown
    if settings.scheduler_enabled:
        from app.scheduler import get_scheduler
        get_scheduler().shutdown(wait=False)
        logger.info("APScheduler stopped.")

    from app.database import engine
    await engine.dispose()
    logger.info("Database engine disposed.")


# ──────────────────────────── App factory ────────────────────────────────────

def create_app() -> FastAPI:
    app = FastAPI(
        title=settings.app_name,
        version=settings.app_version,
        description=(
            "## Threat Intelligence Aggregator\n\n"
            "Collects, normalises, and enriches Indicators of Compromise (IoCs) "
            "from open-source threat feeds.\n\n"
            "### Key endpoints\n"
            "- **POST /api/v1/enrich** — enrich any IP, domain, or hash\n"
            "- **GET  /api/v1/iocs** — search/filter the local IoC database\n"
            "- **POST /api/v1/alerts** — create a security alert with auto-enrichment\n"
            "- **POST /api/v1/feeds/ingest** — manually trigger a feed pull\n"
        ),
        docs_url="/docs",
        redoc_url="/redoc",
        openapi_url="/openapi.json",
        lifespan=lifespan,
    )

    # ── CORS
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.allowed_hosts,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # ── Global exception handler
    @app.exception_handler(Exception)
    async def unhandled_exception_handler(request: Request, exc: Exception):
        logger.exception("Unhandled exception on %s %s", request.method, request.url)
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"detail": "An unexpected error occurred.", "code": "INTERNAL_ERROR"},
        )

    # ── Routers
    prefix = settings.api_prefix
    app.include_router(iocs.router, prefix=prefix)
    app.include_router(enrichment.router, prefix=prefix)
    app.include_router(alerts.router, prefix=prefix)
    app.include_router(feeds.router, prefix=prefix)

    # ── Health-check
    @app.get("/health", tags=["Health"], summary="Health check")
    async def health():
        return {"status": "ok", "version": settings.app_version}

    return app


app = create_app()
