
# Fonction pour hacher un mot de passe avec bcrypt
from datetime import datetime, timedelta
from typing import Optional
import bcrypt
import jwt
from helper.config.settings import Settings
app_settings = Settings()

def hash_password(password: str) -> str:
    """Hash a password using bcrypt with the configurable cost factor."""
    # Utilisation du facteur de coût configuré dans app_settings
    cost = app_settings.BCRYPT_COST  
    salt = bcrypt.gensalt(rounds=cost)  
    hashed = bcrypt.hashpw(password.encode('utf-8'), salt)  
    return hashed.decode('utf-8')  

# Fonction pour vérifier un mot de passe en texte clair contre un mot de passe haché
def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify if a plain password matches the hashed password using bcrypt."""
    return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password.encode('utf-8'))


def create_access_token(data: dict) -> str:
        """Create a JWT token with the provided data and expiration."""
        expires_delta = timedelta(minutes=app_settings.ACCESS_TOKEN_EXPIRE_MINUTES)
        to_encode = data.copy()
        if expires_delta:
            expire = datetime.utcnow() + expires_delta
        else:
            expire = datetime.utcnow() + timedelta(minutes=15)
        to_encode.update({"exp": expire})
        encoded_jwt = jwt.encode(to_encode, app_settings.SECRET_KEY, algorithm=app_settings.ALGORITHM)
        return encoded_jwt