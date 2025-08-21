import os
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.staticfiles import StaticFiles
from typing import Dict, List
from jose import jwt, JWTError
from passlib.context import CryptContext
from datetime import datetime, timedelta
from fastapi.middleware.cors import CORSMiddleware

SECRET_KEY =  "a-very-secret-key"  # Use a secure key in production
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

app = FastAPI()
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Mount static files
app.mount("/", StaticFiles(directory="static", html=True), name="static")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Restrict to your front-end URL in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Dummy in-memory user store
fake_users_db = {}  # username: {username, hashed_password}

def get_password_hash(password):
    return pwd_context.hash(password)

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(data: dict, expires_delta: timedelta):
    to_encode = data.copy()
    expire = datetime.utcnow() + expires_delta
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def decode_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload.get("sub")
    except JWTError:
        return None

@app.get("/")
async def root():
    return FileResponse("static/index.html")

@app.post("/register")
async def register(form_data: OAuth2PasswordRequestForm = Depends()):
    if form_data.username in fake_users_db:
        raise HTTPException(status_code=400, detail="Username already registered")
    fake_users_db[form_data.username] = {
        "username": form_data.username,
        "hashed_password": get_password_hash(form_data.password)
    }
    return {"msg": "User registered"}

@app.post("/token")
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = fake_users_db.get(form_data.username)
    if not user or not verify_password(form_data.password, user["hashed_password"]):
        raise HTTPException(status_code=401, detail="Incorrect username or password")
    access_token = create_access_token(
        data={"sub": user["username"]},
        expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    return {"access_token": access_token, "token_type": "bearer"}

class ConnectionManager:
    def __init__(self):
        self.rooms: Dict[str, List[WebSocket]] = {}

    async def connect(self, room: str, websocket: WebSocket):
        await websocket.accept()
        if room not in self.rooms:
            self.rooms[room] = []
        self.rooms[room].append(websocket)

    def disconnect(self, room: str, websocket: WebSocket):
        self.rooms[room].remove(websocket)
        if not self.rooms[room]:
            del self.rooms[room]

    async def send_to_others(self, room: str, message: str, sender: WebSocket):
        for ws in self.rooms.get(room, []):
            if ws != sender:
                await ws.send_text(message)

manager = ConnectionManager()

async def get_current_user_from_token(websocket: WebSocket):
    token = websocket.query_params.get("token")
    if not token:
        await websocket.close(code=4401)
        raise Exception("Missing token")
    username = decode_token(token)
    if not username:
        await websocket.close(code=4401)
        raise Exception("Invalid token")
    return username

@app.websocket("/ws/{room}")
async def websocket_endpoint(websocket: WebSocket, room: str):
    try:
        username = await get_current_user_from_token(websocket)
    except Exception:
        return
    await manager.connect(room, websocket)
    try:
        while True:
            data = await websocket.receive_text()
            await manager.send_to_others(room, data, websocket)
    except WebSocketDisconnect:
        manager.disconnect(room, websocket)
from fastapi.middleware.cors import CORSMiddleware
