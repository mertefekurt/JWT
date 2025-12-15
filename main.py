from fastapi import FastAPI, Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from datetime import timedelta, datetime, timezone
import uuid
from jose import JWTError, jwt
from config import settings
from models import UserCreate, UserLogin, UserResponse, Token, TokenRefresh, UserUpdate, PasswordChange
from jwt_handler import verify_password, get_password_hash, create_access_token, create_refresh_token, verify_token, verify_refresh_token
from token_blacklist import add_to_blacklist
from exceptions import token_exception_handler, jwt_exception_handler, validation_exception_handler, TokenException
from repository import user_repository
from logger import log_request, log_error, log_auth_event, log_security_event

app = FastAPI(title=settings.app_name)
app_start_time = datetime.now(timezone.utc)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=settings.trusted_hosts
)

app.add_exception_handler(TokenException, token_exception_handler)
app.add_exception_handler(JWTError, jwt_exception_handler)
app.add_exception_handler(RequestValidationError, validation_exception_handler)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

if settings.environment == "development":
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
        log_security_event("Registration attempt", f"Username already exists: {user.username}")
        raise HTTPException(status_code=400, detail="Username already registered")
    if user_repository.get_by_email(user.email):
        log_security_event("Registration attempt", f"Email already exists: {user.email}")
        raise HTTPException(status_code=400, detail="Email already registered")
    hashed_password = get_password_hash(user.password)
    new_user = user_repository.create({
        "username": user.username,
        "email": user.email,
        "hashed_password": hashed_password
    })
    log_auth_event("REGISTER", user.username, True)
    return UserResponse(**new_user)

@app.post("/login", response_model=Token)
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        log_auth_event("LOGIN", form_data.username, False)
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
    user_repository.record_login(user["username"])
    log_auth_event("LOGIN", user["username"], True)
    return {"access_token": access_token, "refresh_token": refresh_token, "token_type": "bearer"}

@app.post("/refresh", response_model=Token)
async def refresh_token(token_data: TokenRefresh):
    try:
        token_info = verify_refresh_token(token_data.refresh_token)
        access_token_expires = timedelta(minutes=settings.access_token_expire_minutes)
        new_access_token = create_access_token(
            data={"sub": token_info.username}, expires_delta=access_token_expires
        )
        new_refresh_token = create_refresh_token(data={"sub": token_info.username})
        add_to_blacklist(token_data.refresh_token)
        return {"access_token": new_access_token, "refresh_token": new_refresh_token, "token_type": "bearer"}
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid refresh token")

@app.post("/logout")
async def logout(token: str = Depends(oauth2_scheme)):
    try:
        token_data = verify_token(token)
        add_to_blacklist(token)
        log_auth_event("LOGOUT", token_data.username, True)
        return {"message": "Successfully logged out"}
    except JWTError:
        log_security_event("Logout attempt", "Invalid token")
        raise HTTPException(status_code=401, detail="Invalid token")

@app.get("/users/me", response_model=UserResponse)
async def read_users_me(current_user: dict = Depends(get_current_user)):
    return UserResponse(**current_user)

@app.put("/users/me", response_model=UserResponse)
async def update_user_profile(
    user_update: UserUpdate,
    current_user: dict = Depends(get_current_user)
):
    update_data = {}
    if user_update.email is not None:
        existing_user = user_repository.get_by_email(user_update.email)
        if existing_user and existing_user["username"] != current_user["username"]:
            raise HTTPException(status_code=400, detail="Email already in use")
        update_data["email"] = user_update.email
    
    if user_update.username is not None and user_update.username != current_user["username"]:
        if user_repository.exists(user_update.username):
            raise HTTPException(status_code=400, detail="Username already taken")
        old_username = current_user["username"]
        if user_update.email:
            update_data["email"] = user_update.email
        if update_data:
            user_repository.update(old_username, update_data)
        user_repository.update_username(old_username, user_update.username)
        updated_user = user_repository.get_by_username(user_update.username)
    else:
        updated_user = user_repository.update(current_user["username"], update_data)
    
    if not updated_user:
        raise HTTPException(status_code=404, detail="User not found")
    
    log_auth_event("PROFILE_UPDATE", current_user["username"], True)
    return UserResponse(**updated_user)

@app.post("/users/me/change-password")
async def change_password(
    password_data: PasswordChange,
    current_user: dict = Depends(get_current_user)
):
    if not verify_password(password_data.current_password, current_user["hashed_password"]):
        log_security_event("Password change attempt", f"Invalid current password for user: {current_user['username']}")
        raise HTTPException(status_code=400, detail="Current password is incorrect")
    
    if password_data.current_password == password_data.new_password:
        raise HTTPException(status_code=400, detail="New password must be different from current password")
    
    new_hashed_password = get_password_hash(password_data.new_password)
    user_repository.update(current_user["username"], {"hashed_password": new_hashed_password})
    log_auth_event("PASSWORD_CHANGE", current_user["username"], True)
    return {"message": "Password changed successfully"}


@app.get("/users/me/activity")
async def user_activity(current_user: dict = Depends(get_current_user)):
    username = current_user["username"]
    user = user_repository.get_by_username(username)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return {
        "username": username,
        "created_at": user.get("created_at"),
        "updated_at": user.get("updated_at"),
        "last_login": user.get("last_login"),
        "login_count": user.get("login_count", 0),
    }


@app.delete("/users/me")
async def delete_current_user(
    current_user: dict = Depends(get_current_user),
    token: str = Depends(oauth2_scheme),
):
    deleted = user_repository.delete(current_user["username"])
    if not deleted:
        raise HTTPException(status_code=404, detail="User not found")
    add_to_blacklist(token)
    log_auth_event("DELETE_ACCOUNT", current_user["username"], True)
    return {"message": "User deleted successfully"}

@app.middleware("http")
async def add_process_time_header(request: Request, call_next):
    import time
    request_id = str(uuid.uuid4())
    request.state.request_id = request_id
    start_time = time.time()
    response = await call_next(request)
    process_time = time.time() - start_time
    response.headers["X-Process-Time"] = str(process_time)
    response.headers["X-Request-ID"] = request_id
    log_request(request.method, request.url.path, response.status_code, process_time, request_id)
    return response

@app.get("/health")
async def health_check():
    from token_blacklist import remove_expired_tokens
    cleaned_tokens = remove_expired_tokens()
    return {
        "status": "healthy",
        "service": "JWT Learning API",
        "timestamp": datetime.now().isoformat(),
        "cleaned_expired_tokens": cleaned_tokens
    }

@app.get("/status")
async def status_check():
    from repository import user_repository
    from token_blacklist import blacklisted_tokens
    total_users = len(user_repository.get_all())
    blacklisted_count = len(blacklisted_tokens)
    return {
        "status": "operational",
        "users_count": total_users,
        "blacklisted_tokens": blacklisted_count,
        "token_expiry_minutes": settings.access_token_expire_minutes,
        "refresh_token_expire_days": settings.refresh_token_expire_days,
        "app_version": settings.app_version,
        "environment": settings.environment,
        "log_level": settings.log_level,
        "uptime_seconds": (datetime.now(timezone.utc) - app_start_time).total_seconds(),
    }


@app.get("/version")
async def version():
    return {
        "app_name": settings.app_name,
        "version": settings.app_version,
    }


@app.get("/metrics")
async def metrics():
    from repository import user_repository
    from token_blacklist import blacklisted_tokens
    users = user_repository.get_all()
    total_logins = sum(user.get("login_count", 0) for user in users)
    return {
        "users_count": len(users),
        "total_logins": total_logins,
        "blacklisted_tokens": len(blacklisted_tokens),
    }


@app.get("/blacklist/count")
async def blacklist_count():
    from token_blacklist import blacklisted_tokens, remove_expired_tokens
    removed = remove_expired_tokens()
    return {
        "blacklisted_tokens": len(blacklisted_tokens),
        "expired_removed": removed,
    }


@app.get("/support")
async def support():
    return {
        "email": settings.support_email,
        "service": settings.app_name,
        "version": settings.app_version,
        "environment": settings.environment,
    }


@app.get("/")
async def root():
    return {"message": settings.app_name, "docs": "/docs"}

