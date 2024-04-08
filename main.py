from fastapi import Depends, FastAPI,HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
from datetime import datetime, timedelta

from jose import JWTError, jwt
from passlib.context import CryptContext

SECRET_KEY ="dc7eeee429a2c10de4f9235bad0b03a082213683d30aaaf4f8cd69e7121aa58d"
ALGORITM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES= 30


app = FastAPI()

class Data(BaseModel):
    name: str
    


@app.post("/create/")
async def create(data:Data):
    return {"data":data}

@app.get("/test/")
async def test(item_id:str):
    return {"hello":item_id}

