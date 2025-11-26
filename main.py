from fastapi import FastAPI, Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from datetime import timedelta
from jose import JWTError, jwt
from config import settings
from models import UserCreate, UserLogin, UserResponse, Token, TokenRefresh
from jwt_handler import verify_password, get_password_hash, create_access_token, create_refresh_token, verify_token
from token_blacklist import add_to_blacklist
from exceptions import token_exception_handler, jwt_exception_handler, validation_exception_handler, TokenException
from repository import user_repository

app = FastAPI(title="JWT Learning Project")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=["*"]
)

app.add_exception_handler(TokenException, token_exception_handler)
app.add_exception_handler(JWTError, jwt_exception_handler)
app.add_exception_handler(RequestValidationError, validation_exception_handler)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

user_repository.create({
    "username": "testuser",
    "email": "test@example.com",
    "hashed_password": "$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQoeG6Lruj3vjPGga31lW"
})

def authenticate_user(username: str, password: str):
    user = user_repository.get_by_username(username)
    if not user:
        return False
    if not verify_password(password, user["hashed_password"]):
        return False
    return user

async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        token_data = verify_token(token)
    except JWTError:
        raise credentials_exception
    user = user_repository.get_by_username(token_data.username)
    if user is None:
        raise credentials_exception
    return user

@app.post("/register", response_model=UserResponse)
async def register(user: UserCreate):
    if user_repository.exists(user.username):
        raise HTTPException(status_code=400, detail="Username already registered")
    if user_repository.get_by_email(user.email):
        raise HTTPException(status_code=400, detail="Email already registered")
    hashed_password = get_password_hash(user.password)
    new_user = user_repository.create({
        "username": user.username,
        "email": user.email,
        "hashed_password": hashed_password
    })
    return UserResponse(**new_user)

@app.post("/login", response_model=Token)
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=settings.access_token_expire_minutes)
    access_token = create_access_token(
        data={"sub": user["username"]}, expires_delta=access_token_expires
    )
    refresh_token = create_refresh_token(data={"sub": user["username"]})
    return {"access_token": access_token, "refresh_token": refresh_token, "token_type": "bearer"}

@app.post("/refresh", response_model=Token)
async def refresh_token(token_data: TokenRefresh):
    try:
        token_info = verify_token(token_data.refresh_token)
        payload = jwt.decode(token_data.refresh_token, settings.secret_key, algorithms=[settings.algorithm])
        if payload.get("type") != "refresh":
            raise HTTPException(status_code=401, detail="Invalid token type")
        access_token_expires = timedelta(minutes=settings.access_token_expire_minutes)
        new_access_token = create_access_token(
            data={"sub": token_info.username}, expires_delta=access_token_expires
        )
        new_refresh_token = create_refresh_token(data={"sub": token_info.username})
        return {"access_token": new_access_token, "refresh_token": new_refresh_token, "token_type": "bearer"}
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid refresh token")

@app.post("/logout")
async def logout(token: str = Depends(oauth2_scheme)):
    add_to_blacklist(token)
    return {"message": "Successfully logged out"}

@app.get("/users/me", response_model=UserResponse)
async def read_users_me(current_user: dict = Depends(get_current_user)):
    return UserResponse(**current_user)

@app.middleware("http")
async def add_process_time_header(request: Request, call_next):
    import time
    start_time = time.time()
    response = await call_next(request)
    process_time = time.time() - start_time
    response.headers["X-Process-Time"] = str(process_time)
    return response

@app.get("/")
async def root():
    return {"message": "JWT Learning API", "docs": "/docs"}

