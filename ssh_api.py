import io
import os
import json
import time
import logging
import base64
import paramiko
from typing import Optional
import azure.functions as func
from pydantic import BaseModel, Field, validator

from function_app import app, logger
from keyvault import _kv_get
from settings import (
    SSH_USERNAME_SECRET_NAME, SSH_PASSWORD_SECRET_NAME,
    SSH_PRIVATE_KEY_SECRET_NAME, SSH_PRIVATE_KEY_PASSPHRASE_SECRET_NAME,
    AUTH_PREFERENCE, ALLOW_UNKNOWN_HOSTS,
    DEFAULT_PORT, CONNECT_TIMEOUT, COMMAND_TIMEOUT, MAX_OUTPUT_BYTES
)

# ============ Modelli ============
class SSHRequest(BaseModel):
    host: str
    port: int = DEFAULT_PORT
    command: str
    timeout_sec: float = COMMAND_TIMEOUT
    correlation_id: Optional[str] = None

    @validator("timeout_sec")
    def positive_timeout(cls, v):
        if v <= 0:
            raise ValueError("timeout_sec deve essere > 0")
        return v

# ============ Helpers credenziali ============
def _get_username() -> str:
    val = _kv_get(SSH_USERNAME_SECRET_NAME)
    if not val:
        raise RuntimeError("SSH username non configurato in Key Vault")
    return val

def _get_password() -> Optional[str]:
    if not SSH_PASSWORD_SECRET_NAME:
        return None
    return _kv_get(SSH_PASSWORD_SECRET_NAME) or None

def _get_private_key() -> Optional[tuple]:
    if not SSH_PRIVATE_KEY_SECRET_NAME:
        return None
    raw = _kv_get(SSH_PRIVATE_KEY_SECRET_NAME)
    if not raw:
        return None
    try:
        if raw.strip().startswith("-----BEGIN"):
            pem = raw
        else:
            import base64 as b64
            pem = b64.b64decode(raw).decode("utf-8")
    except Exception:
        pem = raw
    passphrase = _kv_get(SSH_PRIVATE_KEY_PASSPHRASE_SECRET_NAME) if SSH_PRIVATE_KEY_PASSPHRASE_SECRET_NAME else None
    return (pem, passphrase)

def _load_pkey(pem: str, passphrase: Optional[str]):
    try:
        return paramiko.RSAKey.from_private_key(io.StringIO(pem), password=passphrase)
    except Exception:
        try:
            return paramiko.Ed25519Key.from_private_key(io.StringIO(pem), password=passphrase)
        except Exception as e:
            raise RuntimeError(f"Chiave privata non valida o passphrase errata: {e}")

def _choose_auth():
    key_tuple = _get_private_key()
    pwd = _get_password()
    mode = AUTH_PREFERENCE if AUTH_PREFERENCE in ("auto", "key", "password") else "auto"
    if mode == "key":
        if not key_tuple:
            raise RuntimeError("AUTH_PREFERENCE=key ma la chiave non è configurata")
        pkey = _load_pkey(*key_tuple)
        return {"mode": "key", "pkey": pkey}
    if mode == "password":
        if not pwd:
            raise RuntimeError("AUTH_PREFERENCE=password ma la password non è configurata")
        return {"mode": "password", "password": pwd}
    if key_tuple:
        pkey = _load_pkey(*key_tuple)
        return {"mode": "key", "pkey": pkey}
    if pwd:
        return {"mode": "password", "password": pwd}
    raise RuntimeError("Nessuna credenziale SSH configurata")

def _prepare_ssh_client() -> paramiko.SSHClient:
    client = paramiko.SSHClient()
    if ALLOW_UNKNOWN_HOSTS:
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    else:
        client.load_system_host_keys()
        client.set_missing_host_key_policy(paramiko.RejectPolicy())
    return client

def _exec_command(client: paramiko.SSHClient, command: str, timeout_sec: float):
    started = time.time()
    stdin, stdout, stderr = client.exec_command(command.strip(), timeout=timeout_sec)
    if stdin:
        try:
            stdin.close()
        except Exception:
            pass

    def read_limited(stream):
        buf = bytearray()
        truncated = False
        deadline = started + timeout_sec
        while True:
            now = time.time()
            if now > deadline:
                raise TimeoutError("Timeout lettura output")
            chan = getattr(stream, "channel", None)
            if chan is not None and (chan.recv_ready() or chan.recv_stderr_ready()):
                chunk = stream.read(min(4096, MAX_OUTPUT_BYTES - len(buf)))
                if not chunk:
                    break
                if not isinstance(chunk, (bytes, bytearray)):
                    chunk = chunk.encode()
                buf += chunk
                if len(buf) >= MAX_OUTPUT_BYTES:
                    truncated = True
                    break
            if chan is not None and chan.exit_status_ready() and not chan.recv_ready() and not chan.recv_stderr_ready():
                break
            time.sleep(0.01)
        return bytes(buf), truncated

    out_bytes, out_trunc = read_limited(stdout)
    err_bytes, err_trunc = read_limited(stderr)
    try:
        exit_status = stdout.channel.recv_exit_status()
    except Exception:
        exit_status = None
    finished = time.time()
    return {
        "exit_status": exit_status,
        "stdout": out_bytes.decode(errors="replace"),
        "stderr": err_bytes.decode(errors="replace"),
        "stdout_truncated": out_trunc,
        "stderr_truncated": err_trunc,
        "started_at": started,
        "finished_at": finished,
        "duration_ms": int((finished - started) * 1000)
    }

# ============ Route ============
@app.route(route="ssh/exec", methods=["POST"], auth_level=func.AuthLevel.FUNCTION)
def ssh_exec(req: func.HttpRequest) -> func.HttpResponse:
    request_id = req.headers.get("x-correlation-id") or req.headers.get("x-request-id") or os.urandom(8).hex()
    try:
        payload = req.get_json()
    except ValueError:
        return func.HttpResponse(json.dumps({"error": "JSON non valido", "request_id": request_id}),
                                 status_code=400, mimetype="application/json")

    try:
        data = SSHRequest(**payload)
    except Exception as e:
        return func.HttpResponse(json.dumps({"error": "ValidationError", "message": str(e), "request_id": request_id}),
                                 status_code=400, mimetype="application/json")

    try:
        username = _get_username()
        auth = _choose_auth()
    except Exception as e:
        logger.error("KV/credentials error: %s", str(e))
        return func.HttpResponse(json.dumps({"error": "CredentialsError", "message": str(e), "request_id": request_id}),
                                 status_code=500, mimetype="application/json")

    client = _prepare_ssh_client()
    try:
        if auth["mode"] == "password":
            client.connect(
                hostname=data.host, port=data.port, username=username,
                password=auth["password"],
                timeout=CONNECT_TIMEOUT, banner_timeout=CONNECT_TIMEOUT, auth_timeout=CONNECT_TIMEOUT
            )
        else:
            client.connect(
                hostname=data.host, port=data.port, username=username,
                pkey=auth["pkey"],
                timeout=CONNECT_TIMEOUT, banner_timeout=CONNECT_TIMEOUT, auth_timeout=CONNECT_TIMEOUT
            )

        result = _exec_command(client, data.command, data.timeout_sec)
        resp = {
            "host": data.host,
            "port": data.port,
            "username_source": "KeyVault",
            "auth_mode": auth["mode"],
            "command_executed": data.command.strip(),
            **result,
            "request_id": request_id
        }
        status = 200 if result["exit_status"] == 0 else 207
        return func.HttpResponse(json.dumps(resp), status_code=status, mimetype="application/json")

    except TimeoutError as te:
        return func.HttpResponse(json.dumps({"error": "Timeout", "message": str(te), "request_id": request_id}),
                                 status_code=408, mimetype="application/json")
    except paramiko.AuthenticationException:
        return func.HttpResponse(json.dumps({"error": "AuthFailed", "message": "Autenticazione SSH fallita", "request_id": request_id}),
                                 status_code=401, mimetype="application/json")
    except paramiko.SSHException as se:
        return func.HttpResponse(json.dumps({"error": "SSHError", "message": str(se), "request_id": request_id}),
                                 status_code=502, mimetype="application/json")
    except Exception:
        logger.exception("Unhandled error in ssh_exec")
        return func.HttpResponse(json.dumps({"error": "InternalError", "message": "Errore interno", "request_id": request_id}),
                                 status_code=500, mimetype="application/json")
    finally:
        try:
            client.close()
        except Exception:
            pass