from fastapi import HTTPException, status
from helper.config.settings import settings
from helper.external.auth import ExternalAuth
import httpx
import logging
from typing import Any, Dict
from fastapi_limiter.depends import RateLimiter
from fastapi_limiter import FastAPILimiter
from redis.asyncio import Redis

logger = logging.getLogger(__name__)

# class ExternalClient:
#     def __init__(self):
#         self.base_url = settings.EXTERNAL_API_URL
#         self.auth = ExternalAuth()
#         self.timeout = settings.EXTERNAL_TIMEOUT_SECONDS
#         self.rate_limiter = RateLimiter(
#             times=settings.EXTERNAL_RATE_LIMIT_REQUESTS,
#             seconds=60,
#         )

#     async def initialize(self):
#         """Initialise le client Redis pour le rate limiting."""
#         redis = Redis(host=settings.REDIS_HOST, port=settings.REDIS_PORT, db=settings.REDIS_DB)
#         await FastAPILimiter.init(redis)

#     async def _make_request(
#         self,
#         method: str,
#         endpoint: str,
#         data: Dict[str, Any] = None,
#         params: Dict[str, Any] = None,
#         headers: Dict[str, str] = None,
#     ) -> Dict[str, Any]:
#         """Effectue une requête HTTP sécurisée vers un système externe."""
#         try:
#             # Obtenir le token OAuth 2.0
#             access_token = await self.auth.get_access_token()
#             default_headers = {
#                 "Authorization": f"Bearer {access_token}",
#                 "Content-Type": "application/json",
#                 "Accept": "application/json",
#             }
#             if headers:
#                 default_headers.update(headers)

#             async with httpx.AsyncClient(verify=True, timeout=self.timeout) as client:
#                 response = await client.request(
#                     method=method,
#                     url=f"{self.base_url}{endpoint}",
#                     json=data,
#                     params=params,
#                     headers=default_headers,
#                 )
#                 response.raise_for_status()
#                 logger.info(f"✅ Requête réussie : {method} {endpoint}")
#                 return response.json()
#         except httpx.HTTPStatusError as e:
#             logger.error(f"❌ Erreur HTTP : {str(e)} - Statut : {e.response.status_code}")
#             raise HTTPException(status_code=e.response.status_code, detail="Échec de la requête externe")
#         except httpx.RequestError as e:
#             logger.error(f"❌ Erreur réseau : {str(e)}")
#             raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Service externe indisponible")
#         except Exception as e:
#             logger.error(f"❌ Erreur inattendue : {str(e)}")
#             raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Erreur serveur")

#     async def get(self, endpoint: str, params: Dict[str, Any] = None) -> Dict[str, Any]:
#         """Effectue une requête GET sécurisée."""
#         return await self._make_request("GET", endpoint, params=params)

#     async def post(self, endpoint: str, data: Dict[str, Any] = None) -> Dict[str, Any]:
#         """Effectue une requête POST sécurisée."""
#         return await self._make_request("POST", endpoint, data=data)

#     async def put(self, endpoint: str, data: Dict[str, Any] = None) -> Dict[str, Any]:
#         """Effectue une requête PUT sécurisée."""
#         return await self._make_request("PUT", endpoint, data=data)

#     async def delete(self, endpoint: str, params: Dict[str, Any] = None) -> Dict[str, Any]:
#         """Effectue une requête DELETE sécurisée."""
#         return await self._make_request("DELETE", endpoint, params=params)

class ExternalClient:
    async def initialize(self):
        # Suppression de FastAPILimiter ou autre logique dépendant de Redis
        print("✅ ExternalClient ready (no Redis dependency)")

external_client = ExternalClient()