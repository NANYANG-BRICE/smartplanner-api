import os
import logging
from helper.config.settings import settings

logger = logging.getLogger(__name__)

def create_directory_if_not_exists(path: str):
    if not os.path.exists(path):
        os.makedirs(path, exist_ok=True)
        logger.info(f"✅ Dossier créé : {path}")
    else:
        logger.debug(f"📁 Dossier déjà présent : {path}")

def init_upload_directories():
    logger.info("📦 Initialisation des répertoires d'upload...")
    create_directory_if_not_exists(settings.UPLOAD_LOGO_DIR)
    create_directory_if_not_exists(settings.UPLOAD_PICTURE_DIR)
    create_directory_if_not_exists(settings.UPLOAD_QRCODE_DIR)
    create_directory_if_not_exists(settings.BACKUP_DIR)
    create_directory_if_not_exists(settings.LOG_DIR)