import httpx
import jwt
from fastapi import HTTPException, status
from helper.config.settings import settings
import logging
from datetime import datetime, timedelta
from typing import Optional, Dict

logger = logging.getLogger(__name__)

class ExternalAuth:
    def __init__(self):
        self.client_id = settings.EXTERNAL_CLIENT_ID
        self.client_secret = settings.EXTERNAL_CLIENT_SECRET
        self.token_url = settings.EXTERNAL_TOKEN_URL
        self.audience = settings.EXTERNAL_AUDIENCE
        self._access_token: Optional[str] = None
        self._token_expiry: Optional[datetime] = None

    async def get_access_token(self) -> str:
        """Récupère un token OAuth 2.0 pour l'authentification."""
        if self._access_token and self._token_expiry and self._token_expiry > datetime.utcnow():
            return self._access_token

        try:
            async with httpx.AsyncClient(verify=True, timeout=settings.EXTERNAL_TIMEOUT_SECONDS) as client:
                response = await client.post(
                    self.token_url,
                    data={
                        "grant_type": "client_credentials",
                        "client_id": self.client_id,
                        "client_secret": self.client_secret,
                        "audience": self.audience if self.audience else None,
                    },
                )
                response.raise_for_status()
                token_data = response.json()
                self._access_token = token_data["access_token"]
                self._token_expiry = datetime.utcnow() + timedelta(seconds=token_data["expires_in"] - 60)
                logger.info("✅ Token OAuth 2.0 obtenu avec succès")
                return self._access_token
        except httpx.HTTPStatusError as e:
            logger.error(f"❌ Échec de l'obtention du token : {str(e)}")
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Échec de l'authentification externe")
        except Exception as e:
            logger.error(f"❌ Erreur inattendue lors de l'authentification : {str(e)}")
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Erreur serveur")

    async def verify_jwt(self, token: str) -> Dict:
        """Vérifie la validité d'un token JWT reçu d'un système externe."""
        try:
            payload = jwt.decode(
                token,
                settings.SECRET_KEY,
                algorithms=[settings.ALGORITHM],
                audience=self.audience,
                options={"verify_signature": True, "verify_exp": True},
            )
            logger.debug(f"✅ Token JWT vérifié : {payload}")
            return payload
        except jwt.ExpiredSignatureError:
            logger.error("❌ Token JWT expiré")
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token expiré")
        except jwt.InvalidTokenError as e:
            logger.error(f"❌ Token JWT invalide : {str(e)}")
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token invalide")