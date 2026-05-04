import os
import hmac
import json
import base64
import sqlite3
import secrets
import time
from pathlib import Path
from hashlib import sha256
from datetime import datetime, timedelta, timezone
from typing import Optional

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Depends, Header, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field


# =========================
# CARREGAR .ENV
# =========================

load_dotenv()


# =========================
# CONFIG
# =========================

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "database.db"

ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "135790")
SECRET_KEY = os.getenv("SECRET_KEY", "troque-essa-chave-secreta")
TOKEN_MINUTES = int(os.getenv("TOKEN_MINUTES", "1440"))

ALLOWED_ORIGINS = os.getenv(
    "ALLOWED_ORIGINS",
    "http://localhost:3000,http://localhost:5173,http://localhost:8888"
).split(",")

MAX_GENERATE_AMOUNT = int(os.getenv("MAX_GENERATE_AMOUNT", "500"))


app = FastAPI(
    title="zGuylheme Key API",
    version="1.1.1"
)


app.add_middleware(
    CORSMiddleware,
    allow_origins=[origin.strip() for origin in ALLOWED_ORIGINS if origin.strip()],
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)


# =========================
# SECURITY HEADERS
# =========================

@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)

    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"

    return response


# =========================
# MODELS
# =========================

class LoginBody(BaseModel):
    password: str = Field(min_length=1, max_length=200)


class CreateKeyBody(BaseModel):
    duration_days: int = Field(ge=1, le=365)


class KeyBody(BaseModel):
    key: str = Field(min_length=5, max_length=80)


class ValidateKeyBody(BaseModel):
    key: str = Field(min_length=5, max_length=80)


class GenerateBody(BaseModel):
    key: str = Field(min_length=5, max_length=80)
    type: str = Field(min_length=2, max_length=30)
    amount: int = Field(ge=1, le=500)


# =========================
# RATE LIMIT SIMPLES
# =========================

RATE_LIMIT_STORE = {}


def get_client_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for")

    if forwarded:
        return forwarded.split(",")[0].strip()

    if request.client:
        return request.client.host

    return "unknown"


def rate_limit(ip: str, action: str, limit: int, window_seconds: int):
    now = time.time()
    key = f"{ip}:{action}"

    bucket = RATE_LIMIT_STORE.get(key, [])
    bucket = [timestamp for timestamp in bucket if now - timestamp < window_seconds]

    if len(bucket) >= limit:
        raise HTTPException(
            status_code=429,
            detail="Muitas tentativas. Aguarde um pouco."
        )

    bucket.append(now)
    RATE_LIMIT_STORE[key] = bucket


# =========================
# DATABASE
# =========================

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    cur = conn.cursor()

    cur.execute("""
        CREATE TABLE IF NOT EXISTS keys (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            key TEXT UNIQUE NOT NULL,
            duration_days INTEGER NOT NULL,
            active INTEGER NOT NULL DEFAULT 1,
            offline INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            offline_at TEXT,
            online_at TEXT
        )
    """)

    conn.commit()
    conn.close()


@app.on_event("startup")
def startup():
    init_db()


# =========================
# HELPERS
# =========================

def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat()


def parse_iso(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def normalize_key(key: str) -> str:
    return key.strip().upper()


def normalize_service_type(service_type: str) -> str:
    value = service_type.strip().lower()

    aliases = {
        "youtube": "yt",
        "youTube": "yt",
        "yt": "yt",
        "canva": "canva",
        "spotify": "spotify",
        "deezer": "deezer",
    }

    return aliases.get(value, value)


def generate_key() -> str:
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"

    def part():
        return "".join(secrets.choice(alphabet) for _ in range(4))

    return f"KNUZ-{part()}-{part()}-{part()}"


def generate_code(length: int = 15) -> str:
    chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    return "".join(secrets.choice(chars) for _ in range(length))


def create_token() -> str:
    payload = {
        "type": "admin",
        "exp": iso(now_utc() + timedelta(minutes=TOKEN_MINUTES)),
        "nonce": secrets.token_hex(16)
    }

    payload_json = json.dumps(payload, separators=(",", ":")).encode()
    payload_b64 = base64.urlsafe_b64encode(payload_json).decode().rstrip("=")

    signature = hmac.new(
        SECRET_KEY.encode(),
        payload_b64.encode(),
        sha256
    ).digest()

    signature_b64 = base64.urlsafe_b64encode(signature).decode().rstrip("=")

    return f"{payload_b64}.{signature_b64}"


def verify_token(token: str) -> bool:
    try:
        payload_b64, signature_b64 = token.split(".")

        expected_signature = hmac.new(
            SECRET_KEY.encode(),
            payload_b64.encode(),
            sha256
        ).digest()

        received_signature = base64.urlsafe_b64decode(signature_b64 + "===")

        if not hmac.compare_digest(expected_signature, received_signature):
            return False

        payload_json = base64.urlsafe_b64decode(payload_b64 + "===")
        payload = json.loads(payload_json)

        if payload.get("type") != "admin":
            return False

        exp = parse_iso(payload.get("exp"))

        if now_utc() > exp:
            return False

        return True

    except Exception:
        return False


def require_admin(authorization: Optional[str] = Header(default=None)):
    if not authorization:
        raise HTTPException(status_code=401, detail="Token ausente.")

    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Token inválido.")

    token = authorization.replace("Bearer ", "", 1).strip()

    if not verify_token(token):
        raise HTTPException(status_code=401, detail="Sessão expirada ou inválida.")

    return True


def row_to_key(row: sqlite3.Row) -> dict:
    expires_at = parse_iso(row["expires_at"])
    expired = now_utc() > expires_at

    return {
        "id": row["id"],
        "key": row["key"],
        "duration_days": row["duration_days"],
        "active": bool(row["active"]),
        "offline": bool(row["offline"]),
        "expired": expired,
        "created_at": row["created_at"],
        "expires_at": row["expires_at"],
        "offline_at": row["offline_at"],
        "online_at": row["online_at"],
    }


def get_key_from_db(key: str) -> Optional[sqlite3.Row]:
    conn = get_db()
    cur = conn.cursor()

    cur.execute("SELECT * FROM keys WHERE key = ?", (normalize_key(key),))
    row = cur.fetchone()

    conn.close()
    return row


def validate_key_data(key: str) -> dict:
    row = get_key_from_db(key)

    if not row:
        return {
            "valid": False,
            "status": "invalid",
            "message": "Key inválida."
        }

    item = row_to_key(row)

    if item["offline"] or not item["active"]:
        return {
            "valid": False,
            "status": "offline",
            "message": "Key offline."
        }

    if item["expired"]:
        return {
            "valid": False,
            "status": "expired",
            "message": "Key expirada."
        }

    return {
        "valid": True,
        "status": "active",
        "message": "Key válida.",
        "key": item["key"],
        "expires_at": item["expires_at"]
    }


def build_generated_link(service_type: str, code: str) -> str:
    service_type = normalize_service_type(service_type)

    if service_type == "canva":
        return f"https://www.canva.com/pro/?utm_medium={code}"

    if service_type == "spotify":
        return f"https://www.spotify.com/br-pt/premium/?utm_medium={code}"

    if service_type == "deezer":
        return f"https://www.deezer.com/pt/offers/?utm_medium={code}"

    if service_type == "yt":
        return f"https://www.youtube.com/premium?utm_medium={code}"

    raise HTTPException(status_code=400, detail="Tipo inválido.")


# =========================
# ROTAS BASE
# =========================

@app.get("/")
def home():
    return {
        "online": True,
        "message": "KNUZ Key API funcionando.",
        "version": "1.1.1"
    }


@app.get("/health")
def health():
    return {
        "ok": True,
        "time": iso(now_utc())
    }


# =========================
# ROTAS ADMIN
# =========================

@app.post("/admin/login")
def admin_login(body: LoginBody, request: Request):
    ip = get_client_ip(request)
    rate_limit(ip, "admin_login", limit=8, window_seconds=300)

    password_ok = hmac.compare_digest(body.password, ADMIN_PASSWORD)

    if not password_ok:
        raise HTTPException(status_code=401, detail="Senha incorreta.")

    token = create_token()

    return {
        "token": token,
        "expires_in_minutes": TOKEN_MINUTES
    }


@app.get("/admin/keys")
def list_keys(_: bool = Depends(require_admin)):
    conn = get_db()
    cur = conn.cursor()

    cur.execute("SELECT * FROM keys ORDER BY id DESC")
    rows = cur.fetchall()

    conn.close()

    return {
        "keys": [row_to_key(row) for row in rows]
    }


@app.post("/admin/keys/create")
def create_key(body: CreateKeyBody, _: bool = Depends(require_admin)):
    conn = get_db()
    cur = conn.cursor()

    created_at = now_utc()
    expires_at = created_at + timedelta(days=body.duration_days)

    for _attempt in range(10):
        key = generate_key()

        try:
            cur.execute("""
                INSERT INTO keys (
                    key,
                    duration_days,
                    active,
                    offline,
                    created_at,
                    expires_at
                )
                VALUES (?, ?, 1, 0, ?, ?)
            """, (
                key,
                body.duration_days,
                iso(created_at),
                iso(expires_at)
            ))

            conn.commit()
            conn.close()

            return {
                "key": key,
                "duration_days": body.duration_days,
                "active": True,
                "offline": False,
                "created_at": iso(created_at),
                "expires_at": iso(expires_at)
            }

        except sqlite3.IntegrityError:
            continue

    conn.close()
    raise HTTPException(status_code=500, detail="Não foi possível gerar uma key única.")


@app.post("/admin/keys/offline")
def set_key_offline(body: KeyBody, _: bool = Depends(require_admin)):
    key = normalize_key(body.key)

    conn = get_db()
    cur = conn.cursor()

    cur.execute("SELECT * FROM keys WHERE key = ?", (key,))
    row = cur.fetchone()

    if not row:
        conn.close()
        raise HTTPException(status_code=404, detail="Key não encontrada.")

    cur.execute("""
        UPDATE keys
        SET active = 0,
            offline = 1,
            offline_at = ?
        WHERE key = ?
    """, (
        iso(now_utc()),
        key
    ))

    conn.commit()
    conn.close()

    return {
        "success": True,
        "message": "Key ficou offline."
    }


@app.post("/admin/keys/online")
def set_key_online(body: KeyBody, _: bool = Depends(require_admin)):
    key = normalize_key(body.key)

    conn = get_db()
    cur = conn.cursor()

    cur.execute("SELECT * FROM keys WHERE key = ?", (key,))
    row = cur.fetchone()

    if not row:
        conn.close()
        raise HTTPException(status_code=404, detail="Key não encontrada.")

    expires_at = parse_iso(row["expires_at"])

    if now_utc() > expires_at:
        conn.close()
        raise HTTPException(status_code=400, detail="Key expirada. Não é possível ativar.")

    cur.execute("""
        UPDATE keys
        SET active = 1,
            offline = 0,
            online_at = ?
        WHERE key = ?
    """, (
        iso(now_utc()),
        key
    ))

    conn.commit()
    conn.close()

    return {
        "success": True,
        "message": "Key ativada."
    }


# =========================
# ROTAS DO SITE PRINCIPAL
# =========================

@app.post("/validate-key")
def validate_key(body: ValidateKeyBody, request: Request):
    ip = get_client_ip(request)
    rate_limit(ip, "validate_key", limit=60, window_seconds=300)

    return validate_key_data(body.key)


@app.post("/generate")
def generate_links(body: GenerateBody, request: Request):
    ip = get_client_ip(request)
    rate_limit(ip, "generate", limit=30, window_seconds=300)

    validation = validate_key_data(body.key)

    if not validation.get("valid"):
        return {
            "success": False,
            "status": validation.get("status", "invalid"),
            "message": validation.get("message", "Key inválida.")
        }

    service_type = normalize_service_type(body.type)
    amount = min(body.amount, MAX_GENERATE_AMOUNT)

    results = []

    for _ in range(amount):
        code = generate_code(15)
        link = build_generated_link(service_type, code)
        results.append(link)

    return {
        "success": True,
        "status": "generated",
        "type": service_type,
        "amount": amount,
        "expires_at": validation.get("expires_at"),
        "results": results
    }
