import os
import hmac
import json
import base64
import sqlite3
import secrets
from pathlib import Path
from hashlib import sha256
from datetime import datetime, timedelta, timezone
from typing import Optional

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Depends, Header
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


app = FastAPI(
    title="KNUZ Key API",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[origin.strip() for origin in ALLOWED_ORIGINS if origin.strip()],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# =========================
# MODELS
# =========================

class LoginBody(BaseModel):
    password: str = Field(min_length=1)


class CreateKeyBody(BaseModel):
    duration_days: int = Field(ge=1, le=365)


class KeyBody(BaseModel):
    key: str = Field(min_length=5)


class ValidateKeyBody(BaseModel):
    key: str = Field(min_length=5)


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


def generate_key() -> str:
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"

    def part():
        return "".join(secrets.choice(alphabet) for _ in range(4))

    return f"KNUZ-{part()}-{part()}-{part()}"


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

    cur.execute("SELECT * FROM keys WHERE key = ?", (key.strip(),))
    row = cur.fetchone()

    conn.close()
    return row


# =========================
# ROTAS
# =========================

@app.get("/")
def home():
    return {
        "online": True,
        "message": "KNUZ Key API funcionando."
    }


@app.post("/admin/login")
def admin_login(body: LoginBody):
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
    conn = get_db()
    cur = conn.cursor()

    cur.execute("SELECT * FROM keys WHERE key = ?", (body.key.strip(),))
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
        body.key.strip()
    ))

    conn.commit()
    conn.close()

    return {
        "success": True,
        "message": "Key ficou offline."
    }


@app.post("/admin/keys/online")
def set_key_online(body: KeyBody, _: bool = Depends(require_admin)):
    conn = get_db()
    cur = conn.cursor()

    cur.execute("SELECT * FROM keys WHERE key = ?", (body.key.strip(),))
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
        body.key.strip()
    ))

    conn.commit()
    conn.close()

    return {
        "success": True,
        "message": "Key ativada."
    }


@app.post("/validate-key")
def validate_key(body: ValidateKeyBody):
    key = body.key.strip()
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