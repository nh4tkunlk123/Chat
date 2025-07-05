from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlalchemy.orm import Session

# Import các thành phần từ các file khác trong project
import crud
import models
import schemas
from database import get_db


# --- Cấu hình bảo mật ---
SECRET_KEY = "YOUR_SUPER_SECRET_KEY_CHANGE_THIS" #KEY ở đây
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/login/")


# --- Các hàm tiện ích (Utility Functions) ---

def verify_password(plain_password, hashed_password):
    """So sánh mật khẩu thuần với mật khẩu đã được băm."""
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    """Băm mật khẩu."""
    return pwd_context.hash(password)

def create_access_token(data: dict):
    """Tạo một JWT access token mới."""
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


# --- Các hàm xử lý (Logic Functions) ---

def authenticate_user(db: Session, username: str, password: str) -> Optional[models.User]:
    """
    Xác thực người dùng từ username và password.
    Trả về object User nếu hợp lệ, None nếu không.
    """
    user = crud.get_user_by_username(db, username)
    if not user or not verify_password(password, user.hashed_password):
        return None
    return user
    
def get_user_from_token(db: Session, token: str) -> Optional[models.User]:
    """
    Giải mã token và lấy thông tin người dùng từ database.
    Dùng cho cả WebSocket và các dependency.
    """
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            return None
        token_data = schemas.TokenData(username=username)
    except JWTError:
        return None # Token không hợp lệ hoặc đã hết hạn
    
    user = crud.get_user_by_username(db, username=token_data.username)
    return user


# --- Dependencies cho FastAPI ---

def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    """
    Dependency để lấy user từ token trong request header.
    Bảo vệ các API endpoint yêu cầu đăng nhập.
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    user = get_user_from_token(db, token)
    if user is None:
        raise credentials_exception
    return user

def get_current_active_user(current_user: models.User = Depends(get_current_user)):
    """
    Dependency để kiểm tra xem user có "active" không.

    """
    return current_user
