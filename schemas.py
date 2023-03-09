from pydantic import BaseModel
from typing import Optional, Union
import uuid
import enum

class RoleEnum(enum.Enum):
    admin = "ADMIN"
    member = "MEMBER"
    technician = "TECHNICIAN"

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    id: uuid.UUID

class UserBase(BaseModel):
    firstName: str
    lastName: str
    company: str
    designation: str

class UserUpdate(UserBase):
    password: Union[str, None] = None

class UserCreate(UserBase):
    email: str
    role: RoleEnum
    password: str

class User(UserBase):
    id: uuid.UUID
    email: str
    role: RoleEnum
    class Config:
        orm_mode = True