import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from backend.app.config.settings import settings
from backend.app.database.mongodb import connect_to_mongo, close_mongo_connection
from backend.app.routers.auth_router import router as auth_router
from backend.app.routers.scan_router import router as scan_router
from backend.app.routers.dashboard_router import router as dashboard_router
from backend.app.routers.analytics_router import router as analytics_router
from backend.app.routers.alerts_router import router as alerts_router
from backend.app.routers.reports_router import router as reports_router
from backend.app.routers.model_router import router as model_router
from backend.app.services.ml_engine import ml_engine
from backend.app.services.yara_engine import yara_engine

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("threatlens.main")

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    logger.info("Starting ThreatLens AI Backend...")
    await connect_to_mongo()
    ml_engine.load_models()
    logger.info("ThreatLens AI Backend initialized and ready.")
    yield
    # Shutdown
    logger.info("Shutting down ThreatLens AI Backend...")
    await close_mongo_connection()

app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    description="Enterprise Cybersecurity Malware Classification & Threat Detection System",
    lifespan=lifespan
)

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include Routers
app.include_router(auth_router, prefix=settings.API_PREFIX)
app.include_router(scan_router, prefix=settings.API_PREFIX)
app.include_router(dashboard_router, prefix=settings.API_PREFIX)
app.include_router(analytics_router, prefix=settings.API_PREFIX)
app.include_router(alerts_router, prefix=settings.API_PREFIX)
app.include_router(reports_router, prefix=settings.API_PREFIX)
app.include_router(model_router, prefix=settings.API_PREFIX)

@app.get("/api/health")
async def health_check():
    return {
        "status": "healthy",
        "service": settings.PROJECT_NAME,
        "version": settings.VERSION,
        "ml_engine_loaded": ml_engine.is_loaded,
        "active_model": ml_engine.model_metadata.get("active_model", "Random_Forest"),
        "yara_rules_loaded": yara_engine.rules is not None
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("backend.app.main:app", host="0.0.0.0", port=8000, reload=True)
