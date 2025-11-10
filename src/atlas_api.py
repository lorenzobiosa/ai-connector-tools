# atlas_api.py
# -*- coding: utf-8 -*-
import os
import re
import json
import stat
import time
import tarfile
import urllib.request
import subprocess
import shlex
from typing import Optional, List

import azure.functions as func
from pydantic import BaseModel, Field, validator

from . import app, logger
from .keyvault import _kv_get
from .settings import (
    ATLAS_PUBLIC_KEY_SECRET_NAME, ATLAS_PRIVATE_KEY_SECRET_NAME,
    ATLAS_AUTH_PREFERENCE, ATLAS_DEFAULT_PROFILE,
    ATLAS_CLI_VERSION, ATLAS_CLI_DOWNLOAD_URL_TEMPLATE,
    ATLAS_CLI_PATH, ATLAS_CLI_FALLBACK_PATH
)

# ======================
# Modello richiesta
# ======================
class AtlasExecRequest(BaseModel):
    command: str = Field(..., description="Comando Atlas CLI (es: 'clusters list')")
    profile: Optional[str] = None
    auth_method: Optional[str] = Field(None, description="api_key|profile|auto")
    timeout_sec: Optional[float] = Field(120.0, description="Timeout in secondi")
    correlation_id: Optional[str] = None

    @validator("timeout_sec")
    def positive_timeout_atlas(cls, v):
        if v is None:
            return 120.0
        if v <= 0:
            raise ValueError("timeout_sec deve essere > 0")
        return v


# ======================
# Helpers
# ======================

def _download_without_proxy(url: str, dest_path: str) -> None:
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(url) as resp, open(dest_path, "wb") as f:
        f.write(resp.read())


def _safe_extract_tar(tar_path: str, target_dir: str) -> None:
    os.makedirs(target_dir, exist_ok=True)
    with tarfile.open(tar_path, "r:gz") as tar:
        members: List[tarfile.TarInfo] = []
        base = os.path.realpath(target_dir) + os.sep
        for m in tar.getmembers():
            m_path = os.path.realpath(os.path.join(target_dir, m.name))
            if not m_path.startswith(base):
                logger.warning("Rilevato membro non sicuro nel tar: %s (scartato)", m.name)
                continue
            members.append(m)
        tar.extractall(path=target_dir, members=members)


def _find_cli_binary(root_dir: str) -> str:
    candidates: List[str] = []
    for r, _, files in os.walk(root_dir):
        for f in files:
            if f in ("atlas", "mongocli"):
                p = os.path.join(r, f)
                try:
                    st = os.stat(p)
                    if not (st.st_mode & stat.S_IXUSR):
                        os.chmod(p, st.st_mode | stat.S_IXUSR)
                    candidates.append(p)
                except Exception as e:
                    logger.warning("Impossibile rendere eseguibile %s: %s", p, e)
    for p in candidates:
        if os.path.basename(p) == "atlas":
            return p
    if candidates:
        return candidates[0]
    raise RuntimeError("Atlas CLI binario non trovato dopo estrazione")


def _ensure_atlas_cli_installed(version: Optional[str] = None, force: bool = False) -> str:
    ver = version or ATLAS_CLI_VERSION
    target_path = ATLAS_CLI_PATH
    fallback = ATLAS_CLI_FALLBACK_PATH
    try:
        test_dir = os.path.dirname(target_path)
        os.makedirs(test_dir, exist_ok=True)
        if not os.access(test_dir, os.W_OK | os.X_OK):
            logger.warning("Directory %s non scrivibile, uso fallback %s.", test_dir, fallback)
            target_path = fallback
    except Exception as e:
        logger.warning("Errore creazione dir persistente: %s, uso fallback %s.", e, fallback)
        target_path = fallback

    bin_candidate = os.path.join(target_path, "atlas")
    bin_candidate2 = os.path.join(target_path, "mongocli")
    if not force and (os.path.exists(bin_candidate) or os.path.exists(bin_candidate2)):
        if os.path.exists(bin_candidate) and os.access(bin_candidate, os.X_OK):
            return bin_candidate
        if os.path.exists(bin_candidate2) and os.access(bin_candidate2, os.X_OK):
            return bin_candidate2

    url = ATLAS_CLI_DOWNLOAD_URL_TEMPLATE.format(version=ver)
    logger.info("Scaricando Atlas CLI da %s ...", url)
    try:
        tmp_tar = target_path.rstrip("/\\") + ".tar.gz"
        os.makedirs(target_path, exist_ok=True)
        _download_without_proxy(url, tmp_tar)
        _safe_extract_tar(tmp_tar, target_path)
        for r in (target_path, os.path.join(target_path, "bin")):
            candidate = os.path.join(r, "atlas")
            if os.path.exists(candidate):
                os.chmod(candidate, 0o755)
                return candidate
        return _find_cli_binary(target_path)
    except Exception as e:
        logger.exception("Errore durante il download/install di Atlas CLI: %s", e)
        raise RuntimeError(f"Unable to download/install Atlas CLI: {e}")


def _choose_atlas_auth_method(pub: str, priv: str, prof: str, requested: Optional[str]) -> str:
    if requested:
        req = requested.lower()
        if req not in ("api_key", "profile", "auto"):
            raise RuntimeError(f"auth_method non valido: {requested}")
    else:
        req = (ATLAS_AUTH_PREFERENCE or "api_key").lower()
        if req not in ("api_key", "profile", "auto"):
            req = "api_key"
    if req == "api_key":
        if pub and priv:
            return "api_key"
        raise RuntimeError("Metodo 'api_key' richiesto ma API Key mancante")
    if req == "profile":
        if prof:
            return "profile"
        raise RuntimeError("Metodo 'profile' richiesto ma profilo mancante")
    if pub and priv:
        return "api_key"
    if prof:
        return "profile"
    raise RuntimeError("Nessun metodo di autenticazione disponibile")


def _build_cli_argv(atlas_bin: str, user_command: str, method: str, prof: str) -> List[str]:
    cmd_text = user_command.strip()
    cmd_text = re.sub(r'^(?:\s*)(atlas|mongocli)\s+', '', cmd_text)
    if method == "profile" and prof:
        cmd_text += f" -P {shlex.quote(prof)}"
    return [atlas_bin] + shlex.split(cmd_text)


def _clean_env_for_child(base_env: dict) -> dict:
    env = base_env.copy()
    return env


# ======================
# Route HTTP
# ======================
@app.route(route="atlas/exec", methods=["POST"], auth_level=func.AuthLevel.FUNCTION)
def atlas_exec(req: func.HttpRequest) -> func.HttpResponse:
    request_id = req.headers.get("x-correlation-id") or req.headers.get("x-request-id") or os.urandom(8).hex()
    try:
        body = req.get_json()
    except Exception:
        return func.HttpResponse(json.dumps({"error": "BadRequest", "message": "Corpo JSON non valido", "request_id": request_id}),
                                 status_code=400, mimetype="application/json")
    try:
        data = AtlasExecRequest(**body)
    except Exception as e:
        return func.HttpResponse(json.dumps({"error": "ValidationError", "message": str(e), "request_id": request_id}),
                                 status_code=400, mimetype="application/json")
    try:
        atlas_bin = _ensure_atlas_cli_installed()
    except Exception as e:
        return func.HttpResponse(json.dumps({"error": "AtlasInstallFailed", "message": str(e), "request_id": request_id}),
                                 status_code=502, mimetype="application/json")
    env = _clean_env_for_child(os.environ)
    pub, priv, prof = "", "", data.profile or ATLAS_DEFAULT_PROFILE or ""
    try:
        if ATLAS_PUBLIC_KEY_SECRET_NAME:
            pub = _kv_get(ATLAS_PUBLIC_KEY_SECRET_NAME) or ""
        if ATLAS_PRIVATE_KEY_SECRET_NAME:
            priv = _kv_get(ATLAS_PRIVATE_KEY_SECRET_NAME) or ""
    except Exception as e:
        return func.HttpResponse(json.dumps({"error": "KVError", "message": str(e), "request_id": request_id}),
                                 status_code=502, mimetype="application/json")
    try:
        method = _choose_atlas_auth_method(pub, priv, prof, data.auth_method)
    except Exception as e:
        return func.HttpResponse(json.dumps({"error": "AuthSelectionError", "message": str(e), "request_id": request_id}),
                                 status_code=400, mimetype="application/json")
    if method == "api_key":
        env["MONGODB_ATLAS_PUBLIC_API_KEY"] = pub
        env["MONGODB_ATLAS_PRIVATE_API_KEY"] = priv
    elif method == "profile":
        if not prof:
            return func.HttpResponse(json.dumps({"error": "MissingProfile", "message": "Profilo Atlas non specificato", "request_id": request_id}),
                                     status_code=400, mimetype="application/json")
    try:
        argv = _build_cli_argv(atlas_bin, data.command, method, prof)
    except Exception as e:
        return func.HttpResponse(json.dumps({"error": "CommandBuildError", "message": str(e), "request_id": request_id}),
                                 status_code=400, mimetype="application/json")
    started_at = time.time()
    try:
        proc = subprocess.run(argv, shell=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, timeout=data.timeout_sec)
        finished_at = time.time()
        stdout = proc.stdout.decode("utf-8", errors="ignore")
        stderr = proc.stderr.decode("utf-8", errors="ignore")
        exit_code = proc.returncode
        http_status = 200 if exit_code == 0 else 400
    except subprocess.TimeoutExpired as te:
        finished_at = time.time()
        stdout = te.stdout.decode("utf-8", errors="ignore") if te.stdout else ""
        stderr = te.stderr.decode("utf-8", errors="ignore") if te.stderr else "Timeout scaduto"
        exit_code = None
        http_status = 408
    except Exception as e:
        finished_at = time.time()
        stdout, stderr, exit_code = "", str(e), None
        http_status = 500
    resp = {
        "command_executed": data.command.strip(),
        "argv_executed": argv,
        "auth_mode": method,
        "profile_used": prof if method == "profile" else "",
        "exit_status": exit_code,
        "stdout": stdout,
        "stderr": stderr,
        "started_at": started_at,
        "finished_at": finished_at,
        "duration_ms": int((finished_at - started_at) * 1000),
        "request_id": request_id
    }
    return func.HttpResponse(json.dumps(resp), status_code=http_status, mimetype="application/json")