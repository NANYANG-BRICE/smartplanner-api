import sys
import logging
from pathlib import Path
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from contextlib import asynccontextmanager
from typing import AsyncGenerator

# 🔧 Ajouter le dossier src au PYTHONPATH pour permettre les imports relatifs
sys.path.append(str(Path(__file__).resolve().parent))

# 📦 Imports internes
from helper.database.db import close_db, init_db
from helper.external.client import ExternalClient
from api.router import (
    auth, users, roles, permissions, otp,
    departements, teachers, availabilities,
    students, schools, sections, filieres, specialites,
    cycles, cours, classes, salles, occupations,
    ressources, evenements, reservations, plannings,
    enums
)

# ========================
# Configuration des logs
# ========================
logging.basicConfig(
    level=logging.WARNING,  # Change à ERROR ou CRITICAL si nécessaire
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler()],
)
logger = logging.getLogger("smartplanner")

# ========================
# Clients externes & DB
# ========================
external_client = ExternalClient()

@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    try:
        logger.info("🚀 Initialisation de la base de données...")
        await init_db()
        logger.info("✅ Initialisation réussie")
        yield
    finally:
        logger.info("🛑 Fermeture des connexions...")
        await close_db()
        logger.info("✅ Connexions fermées avec succès")

# ========================
# Application FastAPI
# ========================
app = FastAPI(
    title="SmartPlanner API",
    description="Plateforme de gestion scolaire (établissements, enseignants, étudiants, ressources, emploi du temps).",
    version="1.0.0",
    contact={
        "name": "Support SmartPlanner",
        "email": "support@smartschoolplanner.com"
    },
    lifespan=lifespan,
    docs_url="/docs",             # Swagger à la racine
    redoc_url="/redoc",           # Redoc à /redoc
    openapi_url="/openapi.json",  # Spécification OpenAPI
)

# ========================
# Fichiers statiques
# ========================
STATIC_DIR = Path(__file__).resolve().parent / "static"
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

# ========================
# Routes API
# ========================
API_PREFIX = "/api/v1"
routers = [
    auth, users, roles, permissions, otp,
    departements, teachers, availabilities, students, schools,
    sections, filieres, specialites, cycles, cours,
    classes, salles, occupations, ressources,
    evenements, reservations, plannings, enums
]
for router in routers:
    app.include_router(router, prefix=API_PREFIX)

# ========================
# Endpoint racine
# ========================
@app.get("/", tags=["Root"])
async def root():
    return {"message": "🎓 SmartPlanner API is running!"}
