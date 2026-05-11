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
    "https://veltrix.space,https://painel.veltrix.space,http://localhost:3000,http://localhost:5173,http://localhost:8888"
).split(",")

MAX_GENERATE_AMOUNT = int(os.getenv("MAX_GENERATE_AMOUNT", "500"))


app = FastAPI(
    title="zGuylheme Key API",
    version="1.2.1"
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
    device_id: Optional[str] = Field(default=None, min_length=8, max_length=200)


class GenerateBody(BaseModel):
    key: str = Field(min_length=5, max_length=80)
    type: str = Field(min_length=2, max_length=30)
    amount: int = Field(ge=1, le=500)
    device_id: Optional[str] = Field(default=None, min_length=8, max_length=200)


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
            online_at TEXT,
            device_id TEXT,
            bound_at TEXT,
            last_ip TEXT,
            last_user_agent TEXT
        )
    """)

    cur.execute("PRAGMA table_info(keys)")
    existing_columns = {row["name"] for row in cur.fetchall()}

    migrations = {
        "device_id": "ALTER TABLE keys ADD COLUMN device_id TEXT",
        "bound_at": "ALTER TABLE keys ADD COLUMN bound_at TEXT",
        "last_ip": "ALTER TABLE keys ADD COLUMN last_ip TEXT",
        "last_user_agent": "ALTER TABLE keys ADD COLUMN last_user_agent TEXT",
    }

    for column, sql in migrations.items():
        if column not in existing_columns:
            cur.execute(sql)

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


def normalize_device_id(device_id: Optional[str], request: Request) -> str:
    if device_id and device_id.strip():
        return device_id.strip()

    ip = get_client_ip(request)
    user_agent = request.headers.get("user-agent", "unknown")
    raw = f"{ip}:{user_agent}:{SECRET_KEY}"

    return sha256(raw.encode()).hexdigest()


def normalize_service_type(service_type: str) -> str:
    value = service_type.strip().lower()

    aliases = {
        "youtube": "yt",
        "yt": "yt",
        "canva": "canva",
        "spotify": "spotify",
        "deezer": "deezer",
        "prime": "primevideo",
        "primevideo": "primevideo",
        "prime video": "primevideo",
        "prime-video": "primevideo",
        "amazonprime": "primevideo",
        "amazon prime": "primevideo",
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
    columns = row.keys()

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
        "device_locked": bool(row["device_id"]) if "device_id" in columns else False,
        "bound_at": row["bound_at"] if "bound_at" in columns else None,
        "last_ip": row["last_ip"] if "last_ip" in columns else None,
        "last_user_agent": row["last_user_agent"] if "last_user_agent" in columns else None,
    }


def get_key_from_db(key: str) -> Optional[sqlite3.Row]:
    conn = get_db()
    cur = conn.cursor()

    cur.execute("SELECT * FROM keys WHERE key = ?", (normalize_key(key),))
    row = cur.fetchone()

    conn.close()
    return row


def bind_or_validate_device(key: str, device_id: str, request: Request) -> dict:
    normalized_key = normalize_key(key)
    ip = get_client_ip(request)
    user_agent = request.headers.get("user-agent", "unknown")

    conn = get_db()
    cur = conn.cursor()

    cur.execute("SELECT * FROM keys WHERE key = ?", (normalized_key,))
    row = cur.fetchone()

    if not row:
        conn.close()
        return {
            "valid": False,
            "status": "invalid",
            "message": "Key inválida."
        }

    item = row_to_key(row)

    if item["offline"] or not item["active"]:
        conn.close()
        return {
            "valid": False,
            "status": "offline",
            "message": "Key offline."
        }

    if item["expired"]:
        conn.close()
        return {
            "valid": False,
            "status": "expired",
            "message": "Key expirada."
        }

    saved_device_id = row["device_id"] if "device_id" in row.keys() else None

    if not saved_device_id:
        cur.execute("""
            UPDATE keys
            SET device_id = ?,
                bound_at = ?,
                last_ip = ?,
                last_user_agent = ?
            WHERE key = ?
        """, (
            device_id,
            iso(now_utc()),
            ip,
            user_agent,
            normalized_key
        ))

        conn.commit()
        conn.close()

        return {
            "valid": True,
            "status": "active",
            "message": "Key válida e vinculada a este dispositivo.",
            "key": item["key"],
            "expires_at": item["expires_at"]
        }

    if saved_device_id != device_id:
        conn.close()
        return {
            "valid": False,
            "status": "device_blocked",
            "message": "Essa key já está vinculada a outro dispositivo."
        }

    cur.execute("""
        UPDATE keys
        SET last_ip = ?,
            last_user_agent = ?
        WHERE key = ?
    """, (
        ip,
        user_agent,
        normalized_key
    ))

    conn.commit()
    conn.close()

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

    if service_type == "primevideo":
        return f"https://www.primevideo.com/offers/nonprimehomepage/ref=dv_web_force_root?utm_medium={code}"

    raise HTTPException(status_code=400, detail="Tipo inválido.")


# =========================
# ROTAS BASE
# =========================

@app.get("/")
def home():
    return {
        "online": True,
        "message": "KNUZ Key API funcionando.",
        "version": "1.2.1"
    }


@app.get("/health")
def health():
    return {
        "ok": True,
        "time": iso(now_utc())
    }


@app.get("/api")
def api_home():
    return home()


@app.get("/api/health")
def api_health():
    return health()


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
                    expires_at,
                    device_id,
                    bound_at,
                    last_ip,
                    last_user_agent
                )
                VALUES (?, ?, 1, 0, ?, ?, NULL, NULL, NULL, NULL)
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
                "device_locked": False,
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


@app.post("/admin/keys/reset-device")
def reset_key_device(body: KeyBody, _: bool = Depends(require_admin)):
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
        SET device_id = NULL,
            bound_at = NULL,
            last_ip = NULL,
            last_user_agent = NULL
        WHERE key = ?
    """, (
        key,
    ))

    conn.commit()
    conn.close()

    return {
        "success": True,
        "message": "Dispositivo da key resetado. A próxima pessoa que usar vai vincular novamente."
    }


# =========================
# ROTAS DO SITE PRINCIPAL
# =========================

@app.post("/validate-key")
def validate_key(body: ValidateKeyBody, request: Request):
    ip = get_client_ip(request)
    rate_limit(ip, "validate_key", limit=60, window_seconds=300)

    device_id = normalize_device_id(body.device_id, request)

    return bind_or_validate_device(body.key, device_id, request)


@app.post("/generate")
def generate_links(body: GenerateBody, request: Request):
    ip = get_client_ip(request)
    rate_limit(ip, "generate", limit=30, window_seconds=300)

    device_id = normalize_device_id(body.device_id, request)
    validation = bind_or_validate_device(body.key, device_id, request)

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


# =========================
# ROTAS COM /api
# =========================

@app.post("/api/validate-key")
def api_validate_key(body: ValidateKeyBody, request: Request):
    return validate_key(body, request)


@app.post("/api/generate")
def api_generate_links(body: GenerateBody, request: Request):
    return generate_links(body, request)


# =========================
# ROTAS ADMIN COM /api
# =========================

@app.post("/api/admin/login")
def api_admin_login(body: LoginBody, request: Request):
    return admin_login(body, request)


@app.get("/api/admin/keys")
def api_list_keys(_: bool = Depends(require_admin)):
    return list_keys(_)


@app.post("/api/admin/keys/create")
def api_create_key(body: CreateKeyBody, _: bool = Depends(require_admin)):
    return create_key(body, _)


@app.post("/api/admin/keys/offline")
def api_set_key_offline(body: KeyBody, _: bool = Depends(require_admin)):
    return set_key_offline(body, _)


@app.post("/api/admin/keys/online")
def api_set_key_online(body: KeyBody, _: bool = Depends(require_admin)):
    return set_key_online(body, _)


@app.post("/api/admin/keys/reset-device")
def api_reset_key_device(body: KeyBody, _: bool = Depends(require_admin)):
    return reset_key_device(body, _)
