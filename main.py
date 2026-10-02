import hmac
import os
import secrets
import time
from collections import deque
from datetime import datetime, timedelta, timezone
from typing import Deque, Dict, List, Literal, Optional

import jwt
from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field

# ---------------- Config (set these as env vars on Render) ----------------
ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "")          # REQUIRED for login to work
SECRET_KEY = os.getenv("SECRET_KEY") or secrets.token_urlsafe(32)  # set a fixed one in production
TOKEN_EXPIRE_MINUTES = int(os.getenv("TOKEN_EXPIRE_MINUTES", "720"))
DEVICE_API_KEY = os.getenv("DEVICE_API_KEY", "")          # optional: protects the ESP8266 POST route

OFFLINE_AFTER_SECONDS = int(os.getenv("OFFLINE_AFTER_SECONDS", "60"))
HISTORY_LIMIT = int(os.getenv("HISTORY_LIMIT", "500"))
ALLOWED_ORIGINS = [o.strip() for o in os.getenv("ALLOWED_ORIGINS", "*").split(",")]

MAX_FAILED_LOGINS = 5
LOGIN_WINDOW_SECONDS = 300

if not ADMIN_PASSWORD:
    print("WARNING: ADMIN_PASSWORD is not set. Login is disabled until you set it.")
if not os.getenv("SECRET_KEY"):
    print("WARNING: SECRET_KEY not set. Using a random key; logins reset on every restart.")

app = FastAPI(title="Smart Waste Bin API", version="2.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

bearer_scheme = HTTPBearer(auto_error=False)


# ---------------- Schemas ----------------
class BinReport(BaseModel):
    """Payload sent by the ESP8266."""
    bin_id: str = Field(..., min_length=1, max_length=50)
    status: Literal["full", "not_full"]
    is_full: bool
    distance_cm: float = Field(..., ge=0)
    fill_percent: int = Field(..., ge=0, le=100)


class BinState(BaseModel):
    bin_id: str
    status: Literal["full", "not_full"]
    is_full: bool
    distance_cm: float
    fill_percent: int
    updated_at: datetime
    seconds_since_update: int
    online: bool


class LoginRequest(BaseModel):
    username: str = Field(..., max_length=100)
    password: str = Field(..., max_length=200)


# ---------------- Storage (in memory) ----------------
# Resets on Render restart/redeploy. Swap for Postgres if you need persistence.
latest: Dict[str, dict] = {}
history: Dict[str, Deque[dict]] = {}
failed_logins: Dict[str, Deque[float]] = {}


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _to_state(record: dict) -> BinState:
    age = int((_now() - record["updated_at"]).total_seconds())
    return BinState(**record, seconds_since_update=age, online=age <= OFFLINE_AFTER_SECONDS)


def _safe_equal(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))


# ---------------- Auth helpers ----------------
def _client_ip(request: Request) -> str:
    fwd = request.headers.get("x-forwarded-for")
    if fwd:
        return fwd.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def _check_rate_limit(ip: str) -> None:
    attempts = failed_logins.setdefault(ip, deque())
    now = time.time()
    while attempts and now - attempts[0] > LOGIN_WINDOW_SECONDS:
        attempts.popleft()
    if len(attempts) >= MAX_FAILED_LOGINS:
        raise HTTPException(status_code=429, detail="Too many failed attempts. Try again in a few minutes.")


def require_user(creds: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme)) -> str:
    """Protects dashboard routes: requires a valid Bearer token."""
    if not creds:
        raise HTTPException(status_code=401, detail="Not authenticated", headers={"WWW-Authenticate": "Bearer"})
    try:
        payload = jwt.decode(creds.credentials, SECRET_KEY, algorithms=["HS256"])
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired token", headers={"WWW-Authenticate": "Bearer"})
    return payload["sub"]


def require_device(x_api_key: Optional[str] = Header(default=None)) -> None:
    """Protects the ESP8266 route when DEVICE_API_KEY is set."""
    if DEVICE_API_KEY and not (x_api_key and _safe_equal(x_api_key, DEVICE_API_KEY)):
        raise HTTPException(status_code=401, detail="Invalid device key")


# ---------------- Public routes ----------------
@app.get("/")
def root():
    return {"service": "Smart Waste Bin API", "docs": "/docs"}


@app.get("/health")
def health():
    return {"status": "ok", "time": _now().isoformat()}


@app.post("/api/auth/login")
def login(body: LoginRequest, request: Request):
    if not ADMIN_PASSWORD:
        raise HTTPException(status_code=503, detail="Login is not configured on the server")

    ip = _client_ip(request)
    _check_rate_limit(ip)

    user_ok = _safe_equal(body.username, ADMIN_USERNAME)
    pass_ok = _safe_equal(body.password, ADMIN_PASSWORD)
    if not (user_ok and pass_ok):
        failed_logins[ip].append(time.time())
        raise HTTPException(status_code=401, detail="Incorrect username or password")

    failed_logins.pop(ip, None)
    expires = _now() + timedelta(minutes=TOKEN_EXPIRE_MINUTES)
    token = jwt.encode({"sub": ADMIN_USERNAME, "exp": expires}, SECRET_KEY, algorithm="HS256")
    return {"access_token": token, "token_type": "bearer", "expires_in": TOKEN_EXPIRE_MINUTES * 60}


# ---------------- Device route (ESP8266) ----------------
@app.post("/api/bin/status", status_code=201, dependencies=[Depends(require_device)])
def receive_status(report: BinReport):
    record = {**report.model_dump(), "updated_at": _now()}
    latest[report.bin_id] = record

    if report.bin_id not in history:
        history[report.bin_id] = deque(maxlen=HISTORY_LIMIT)
    history[report.bin_id].append(record)

    return {"message": "received", "bin_id": report.bin_id, "status": report.status}


# ---------------- Protected routes (frontend, login required) ----------------
@app.get("/api/auth/me")
def me(user: str = Depends(require_user)):
    return {"username": user}


@app.get("/api/bin/status", response_model=List[BinState], dependencies=[Depends(require_user)])
def get_all_bins():
    return [_to_state(r) for r in latest.values()]


@app.get("/api/bin/status/{bin_id}", response_model=BinState, dependencies=[Depends(require_user)])
def get_bin(bin_id: str):
    record = latest.get(bin_id)
    if not record:
        raise HTTPException(status_code=404, detail=f"Bin '{bin_id}' not found")
    return _to_state(record)


@app.get("/api/bin/history/{bin_id}", dependencies=[Depends(require_user)])
def get_history(bin_id: str, limit: int = Query(50, ge=1, le=HISTORY_LIMIT)):
    records = history.get(bin_id)
    if not records:
        raise HTTPException(status_code=404, detail=f"No history for '{bin_id}'")
    return list(records)[-limit:][::-1]
