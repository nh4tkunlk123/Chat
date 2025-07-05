# =================================================================
# auth.py
# (Không thay đổi)
# =================================================================

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
SECRET_KEY = "YOUR_SUPER_SECRET_KEY_CHANGE_THIS"  # <-- THAY ĐỔI KEY NÀY
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
        return None  # Token không hợp lệ hoặc đã hết hạn

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
    (Hiện tại chỉ trả về user, có thể mở rộng trong tương lai)
    """
    return current_user


# =================================================================
# schemas.py
# (Không thay đổi)
# =================================================================
from pydantic import BaseModel
from typing import Optional


# Schema cho User
class UserBase(BaseModel):
    username: str


class UserCreate(UserBase):
    password: str


class User(UserBase):
    id: int

    class Config:
        from_attributes = True


# Schema cho Token
class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    username: Optional[str] = None


# Schema cho File Response
class FileResponse(BaseModel):
    filename: str
    url: str
    uploader: str


# =================================================================
# main.py (đã cập nhật)
# File chính của ứng dụng, chứa định nghĩa API và trang test chat.
# =================================================================

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
import os
import shutil
from typing import List

from fastapi import (FastAPI, WebSocket, WebSocketDisconnect, Depends,
                     HTTPException, status, UploadFile, File)
from fastapi.security import OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from starlette.responses import FileResponse, RedirectResponse, HTMLResponse

from sqlalchemy.orm import Session

# Import các thành phần từ các file khác trong project
import models
import schemas
import crud
import auth
from database import engine, get_db

# Tạo các bảng trong database nếu chúng chưa tồn tại
models.Base.metadata.create_all(bind=engine)

# Tạo thư mục để lưu trữ các file được upload lên
UPLOAD_DIRECTORY = "./uploads"
if not os.path.exists(UPLOAD_DIRECTORY):
    os.makedirs(UPLOAD_DIRECTORY)

app = FastAPI(
    title="Discord Clone Backend",
    description="Tài liệu API cho ứng dụng chat.",
    version="1.0.0"
)

# Cấu hình CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount thư mục 'uploads' để có thể truy cập các file đã upload qua URL
app.mount("/files", StaticFiles(directory=UPLOAD_DIRECTORY), name="files")


@app.post("/api/register/", response_model=schemas.User, status_code=status.HTTP_201_CREATED,
          tags=["Users"])
def register_user(user: schemas.UserCreate, db: Session = Depends(get_db)):
    """Đăng ký một người dùng mới."""
    db_user = crud.get_user_by_username(db, username=user.username)
    if db_user:
        raise HTTPException(status_code=400, detail="Username đã được đăng ký")
    return crud.create_user(db=db, user=user)


@app.post("/api/login/", response_model=schemas.Token, tags=["Users"])
def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends(),
                           db: Session = Depends(get_db)):
    """Đăng nhập để nhận về access token."""
    user = auth.authenticate_user(db, username=form_data.username, password=form_data.password)
    if not user:
        raise HTTPException(
            status_code=401,
            detail="Username hoặc password không chính xác",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token = auth.create_access_token(data={"sub": user.username})
    return {"access_token": access_token, "token_type": "bearer"}


@app.get("/api/users/me/", response_model=schemas.User, tags=["Users"])
def read_users_me(current_user: models.User = Depends(auth.get_current_active_user)):
    """Lấy thông tin của người dùng hiện tại (yêu cầu token)."""
    return current_user


# --- Connection Manager và các Endpoint khác ---
class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        self.active_connections.remove(websocket)

    async def broadcast(self, message: str):
        for connection in self.active_connections:
            await connection.send_text(message)


manager = ConnectionManager()


@app.post("/api/uploadfile/", response_model=schemas.FileResponse, tags=["Chat"])
async def upload_file(file: UploadFile = File(...),
                      current_user: models.User = Depends(auth.get_current_active_user)):
    """Tải một file lên server (yêu cầu token)."""
    file_path = os.path.join(UPLOAD_DIRECTORY, file.filename)
    with open(file_path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)
    file_url = f"/files/{file.filename}"

    return {"filename": file.filename, "url": file_url, "uploader": current_user.username}


@app.websocket("/ws/{token}")
async def websocket_endpoint(websocket: WebSocket, token: str, db: Session = Depends(get_db)):
    """Endpoint WebSocket để chat real-time (yêu cầu token trong URL)."""
    user = auth.get_user_from_token(db, token)
    if not user:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return
    username = user.username
    await manager.connect(websocket)
    await manager.broadcast(
        f'{{"user": "Hệ thống", "type": "status", "content": "{username} vừa tham gia phòng chat."}}')
    try:
        while True:
            data = await websocket.receive_text()
            # If the message is a file message, expect JSON with path/msg
            try:
                import json
                msg_obj = json.loads(data)
                if "path" in msg_obj:
                    # Broadcast file message with path and msg
                    # Escape double quotes in message to prevent JSON parsing errors
                    safe_msg = msg_obj.get("msg", "").replace('"', '\\"')
                    message_to_broadcast = json.dumps({
                        "user": username,
                        "type": "file",
                        "path": msg_obj.get("path", ""),
                        "msg": safe_msg
                    })
                    await manager.broadcast(message_to_broadcast)
                    continue
                elif "type" in msg_obj and msg_obj["type"] == "message":
                    # Handle regular message in JSON format
                    safe_content = msg_obj.get("content", "").replace('"', '\\"')
                    message_to_broadcast = json.dumps({
                        "user": username,
                        "type": "message",
                        "content": safe_content
                    })
                    await manager.broadcast(message_to_broadcast)
                    continue
            except json.JSONDecodeError:
                # If not valid JSON, treat as plain text message
                pass

            # Otherwise, treat as normal text message
            safe_text = data.replace('"', '\\"')
            message_to_broadcast = json.dumps({
                "user": username,
                "type": "message",
                "content": safe_text
            })
            await manager.broadcast(message_to_broadcast)
    except WebSocketDisconnect:
        manager.disconnect(websocket)
        await manager.broadcast(
            f'{{"user": "Hệ thống", "type": "status", "content": "{username} đã rời khỏi phòng chat."}}')


# --- Trang Login và Chat ---
@app.get("/", response_class=HTMLResponse, tags=["Pages"])
async def get_root():
    """Chuyển hướng về trang đăng nhập."""
    return RedirectResponse(url="/login")


@app.get("/login", response_class=HTMLResponse, tags=["Pages"])
async def get_login_page():
    """Hiển thị trang đăng nhập."""
    return FileResponse("templates/login.html")


@app.get("/chat", response_class=HTMLResponse, tags=["Pages"])
async def get_chat_page():
    """Hiển thị trang chat (yêu cầu đăng nhập)."""
    return FileResponse("templates/chat.html")
