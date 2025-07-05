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