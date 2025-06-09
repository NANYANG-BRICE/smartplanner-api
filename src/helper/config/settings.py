from typing import List, Optional
from pydantic import EmailStr, HttpUrl
from pydantic_settings import BaseSettings
from helper.utils.enums import AppEnvironment

class Settings(BaseSettings):
    # === App Settings ===
    APP_NAME: str
    APP_ENV: AppEnvironment = AppEnvironment.development
    DEBUG: bool = True
    HOST: str = "0.0.0.0"
    PORT: int = 8000

    # === Database ===
    POSTGRES_USER: str
    POSTGRES_PASSWORD: str
    POSTGRES_DB: str
    POSTGRES_HOST: str
    POSTGRES_PORT: int
    DATABASE_URL: str

    # === JWT Settings ===
    SECRET_KEY: str
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    REFRESH_TOKEN_EXPIRE_MINUTES: int = 1440
    BCRYPT_COST: int = 12

    # === OTP Settings ===
    OTP_LENGTH: int = 6
    OTP_EXPIRE_MINUTES: int = 5

    # === Email Settings ===
    SMTP_SERVER: str
    SMTP_PORT: int
    SMTP_USERNAME: EmailStr
    SMTP_PASSWORD: str
    EMAIL_FROM_NAME: str
    EMAIL_FROM_ADDRESS: EmailStr

    # === Redis ===
    REDIS_HOST: str
    REDIS_PORT: int
    REDIS_DB: int

    # === Uploads & Files ===
    UPLOAD_LOGO_DIR: str
    UPLOAD_PICTURE_DIR: str
    UPLOAD_QRCODE_DIR: str
    ALLOWED_EXTENSIONS: str = "jpg,jpeg,png,pdf,docx"
    MAX_UPLOAD_SIZE_MB: int = 10

    # === Backup Settings ===
    BACKUP_DIR: str = "backups/"
    BACKUP_INTERVAL_HOURS: int = 24

    # === Logging ===
    LOG_LEVEL: str = "info"
    LOG_DIR: str = "logs/"
    LOG_FILE: str = "smartplanner.log"

    # === External Systems ===
    EXTERNAL_API_URL: HttpUrl  # URL du système externe (ex: https://api.external.com)
    EXTERNAL_CLIENT_ID: str    # ID client pour OAuth 2.0
    EXTERNAL_CLIENT_SECRET: str  # Secret client pour OAuth 2.0
    EXTERNAL_TOKEN_URL: HttpUrl  # URL pour récupérer le token OAuth 2.0
    EXTERNAL_AUDIENCE: Optional[str] = None  # Audience pour JWT (optionnel)
    EXTERNAL_RATE_LIMIT_REQUESTS: int = 100  # Limite de requêtes par minute
    EXTERNAL_TIMEOUT_SECONDS: float = 10.0  # Timeout pour les requêtes HTTP

    # === Méthodes utiles ===
    @property
    def allowed_extensions_list(self) -> List[str]:
        return [ext.strip().lower() for ext in self.ALLOWED_EXTENSIONS.split(",")]

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"

# Instance à utiliser dans tout le projet
settings = Settings()