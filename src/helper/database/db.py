from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker
from helper.config.settings import settings
import logging

logger = logging.getLogger(__name__)

# Création du moteur asynchrone pour PostgreSQL
engine = create_async_engine(
    settings.DATABASE_URL,
    echo=settings.DEBUG,  # Active les logs SQL si DEBUG est True
    future=True,
)

# Configuration de la fabrique de sessions asynchrones
AsyncSessionLocal = sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
)

async def get_db():
    """
    Fournit une session de base de données asynchrone pour FastAPI.
    Utilisation dans les routes : async with get_db() as db
    """
    async with AsyncSessionLocal() as session:
        try:
            yield session
        except Exception as e:
            logger.error(f"Erreur dans la session de base de données : {str(e)}")
            await session.rollback()
            raise
        finally:
            await session.close()

async def init_db():
    """
    Initialise la connexion à la base de données et vérifie la connectivité.
    """
    try:
        async with engine.begin() as conn:
            logger.info("✅ Connexion à la base de données établie avec succès")
    except Exception as e:
        logger.error(f"❌ Échec de la connexion à la base de données : {str(e)}")
        raise