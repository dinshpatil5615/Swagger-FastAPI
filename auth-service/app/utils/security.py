import hashlib
from datetime import datetime, timedelta
from jose import jwt
from passlib.context import CryptContext
from fastapi.security import OAuth2PasswordBearer

SECRET_KEY = "your-secret-key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# 🔥 THIS MUST HAVE LEADING SLASH
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/login")


def hash_password(password: str) -> str:
    sha256_hash = hashlib.sha256(password.encode()).hexdigest()
    return pwd_context.hash(sha256_hash)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    sha256_hash = hashlib.sha256(plain_password.encode()).hexdigest()
    return pwd_context.verify(sha256_hash, hashed_password)


def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)