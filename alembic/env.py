import asyncio
import os
import sys
from logging.config import fileConfig
from pathlib import Path
from dotenv import load_dotenv

from sqlalchemy import pool
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine
from sqlalchemy.engine import engine_from_config

from alembic import context

# =========================================
# Initialisation des chemins et de l'env
# =========================================

BASE_DIR = Path(__file__).resolve().parent.parent
SRC_DIR = BASE_DIR / "src"

print(f"path : {SRC_DIR}")
sys.path.append(str(SRC_DIR))  # <-- Cette ligne est essentielle
load_dotenv(BASE_DIR / ".env")

# =========================================
# Import des modèles
# =========================================

from api.models import Base

# =========================================
# Configuration Alembic
# =========================================

config = context.config

if config.config_file_name:
    fileConfig(config.config_file_name)

# =========================================
# Import des modèles et métadonnées
# =========================================

target_metadata = Base.metadata

# =========================================
# Configuration URL de la DB
# =========================================

DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL n'est pas défini dans le fichier .env")

config.set_main_option("sqlalchemy.url", DATABASE_URL)


# =========================================
# Migration hors ligne
# =========================================

def run_migrations_offline() -> None:
    """Exécute les migrations sans connexion DB (génère SQL)."""
    context.configure(
        url=DATABASE_URL,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


# =========================================
# Migration en ligne
# =========================================

async def run_migrations_online() -> None:
    """Exécute les migrations avec une connexion DB."""
    connectable = AsyncEngine(
        engine_from_config(
            config.get_section(config.config_ini_section),
            prefix="sqlalchemy.",
            poolclass=pool.NullPool,
        )
    )

    async with connectable.connect() as connection:
        await connection.run_sync(do_run_migrations)

    await connectable.dispose()


def do_run_migrations(connection):
    context.configure(
        connection=connection,
        target_metadata=target_metadata,
    )
    with context.begin_transaction():
        context.run_migrations()


# =========================================
# Point d'entrée
# =========================================

if context.is_offline_mode():
    run_migrations_offline()
else:
    asyncio.run(run_migrations_online())
