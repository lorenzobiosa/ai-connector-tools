# atlas_api.py
# -*- coding: utf-8 -*-
import os
import re
import json
import stat
import time
import tarfile
import hashlib
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
    """
    Scarica un file disattivando i proxy di ambiente.
    """
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(url) as resp, open(dest_path, "wb") as f:
        f.write(resp.read())


def _safe_extract_tar(tar_path: str, target_dir: str) -> None:
    """
    Estrae un archivio .tar.gz in modo sicuro (no path traversal).
    """
    os.makedirs(target_dir, exist_ok=True)
    with tarfile.open(tar_path, "r:gz") as tar:
        members: List[tarfile.TarInfo] = []
        base = os.path.realpath(target_dir) + os.sep

        for m in tar.getmembers():
            # Evita path assoluti e traversal
            m_path = os.path.realpath(os.path.join(target_dir, m.name))
            if not m_path.startswith(base):
                logger.warning("Rilevato membro non sicuro nel tar: %s (scartato)", m.name)
                continue
            members.append(m)

        tar.extractall(path=target_dir, members=members)


def _find_cli_binary(root_dir: str) -> str:
    """
    Cerca l'eseguibile 'atlas' preferibilmente, in alternativa 'mongocli'.
    Imposta il bit di esecuzione se necessario.
    """
    candidates: List[str] = []
    for r, _, files in os.walk(root_dir):
        for f in files:
            if f == "atlas" or f == "mongocli":
                p = os.path.join(r, f)
                try:
                    st = os.stat(p)
                    if not (st.st_mode & stat.S_IXUSR):
                        os.chmod(p, st.st_mode | stat.S_IXUSR)
                    candidates.append(p)
                except Exception as e:
                    logger.warning("Impossibile rendere eseguibile %s: %s", p, e)

    # Preferisci 'atlas'
    for p in candidates:
        if os.path.basename(p) == "atlas":
            return p

    # Fallback a 'mongocli'
    if candidates:
        return candidates[0]

    raise RuntimeError("Atlas CLI binario non trovato dopo estrazione")


def _ensure_atlas_cli_installed(version: Optional[str] = None, force: bool = False) -> str:
    """
    Garantisce che l'Atlas CLI sia disponibile e ritorna il percorso assoluto del binario.
    - Scarica il tar ufficiale da fastdl.mongodb.org (senza proxy).
    - Estrae in cartella persistente (o fallback) in modo sicuro.
    - Restituisce il percorso del binario 'atlas' (o 'mongocli').
    """
    ver = version or ATLAS_CLI_VERSION
    target_path = ATLAS_CLI_PATH
    fallback = ATLAS_CLI_FALLBACK_PATH

    # Scegli cartella scrivibile
    try:
        test_dir = os.path.dirname(target_path)
        os.makedirs(test_dir, exist_ok=True)
        if not os.access(test_dir, os.W_OK | os.X_OK):
            logger.warning("Directory %s non scrivibile/exec, uso fallback %s.", test_dir, fallback)
            target_path = fallback
    except Exception as e:
        logger.warning("Errore creazione dir persistente per atlas cli: %s, uso fallback %s.", e, fallback)
        target_path = fallback

    # Se già presente
    bin_candidate = os.path.join(target_path, "atlas")
    bin_candidate2 = os.path.join(target_path, "mongocli")
    if not force and (os.path.exists(bin_candidate) or os.path.exists(bin_candidate2)):
        if os.path.exists(bin_candidate) and os.access(bin_candidate, os.X_OK):
            return bin_candidate
        if os.path.exists(bin_candidate2) and os.access(bin_candidate2, os.X_OK):
            return bin_candidate2

    # Scarica ed estrai
    url = ATLAS_CLI_DOWNLOAD_URL_TEMPLATE.format(version=ver)
    logger.info("Scaricando Atlas CLI da %s ...", url)
    try:
        tmp_base = target_path.rstrip("/\\")
        tmp_tar = tmp_base + ".tar.gz"
        os.makedirs(target_path, exist_ok=True)

        _download_without_proxy(url, tmp_tar)
        _safe_extract_tar(tmp_tar, target_path)

        # Prova posizione nota: spesso /<estratto>/bin/atlas
        try:
            for r in (target_path, os.path.join(target_path, "bin")):
                candidate = os.path.join(r, "atlas")
                if os.path.exists(candidate):
                    os.chmod(candidate, 0o755)
                    return candidate
        except Exception:
            pass

        # Scansione generale
        found = _find_cli_binary(target_path)
        return found

    except Exception as e:
        logger.exception("Errore durante il download/install di Atlas CLI: %s", e)
        raise RuntimeError(f"Unable to download/install Atlas CLI: {e}")


def _choose_atlas_auth_method(pub: str, priv: str, prof: str, requested: Optional[str]) -> str:
    """
    Se richiesto esplicitamente, onora 'api_key' o 'profile'.
    Altrimenti, per policy: default = api_key.
    Se mancano le chiavi per api_key → errore esplicito.
    """
    # Normalizza richiesta esplicita
    if requested:
        req = requested.lower()
        if req not in ("api_key", "profile", "auto"):
            raise RuntimeError(f"auth_method non valido: {requested}")
    else:
        # Override della preferenza: default desiderato = api_key
        req = (ATLAS_AUTH_PREFERENCE or "api_key").lower()
        if req not in ("api_key", "profile", "auto"):
            req = "api_key"

    if req == "api_key":
        if pub and priv:
            return "api_key"
        raise RuntimeError("Metodo 'api_key' richiesto ma API Key mancante in Key Vault")

    if req == "profile":
        if prof:
            return "profile"
        raise RuntimeError("Metodo 'profile' richiesto ma 'profile' non specificato")

    # auto → preferisci api_key se possibile, altrimenti profilo, altrimenti errore
    if pub and priv:
        return "api_key"
    if prof:
        return "profile"
    raise RuntimeError("Nessun metodo di autenticazione disponibile (mancano API Key e profilo)")


def _build_cli_argv(atlas_bin: str, user_command: str, method: str, prof: str) -> List[str]:
    """
    Costruisce argv sicuro:
    - Rimuove un eventuale prefisso 'atlas ' o 'mongocli ' inserito nel comando utente.
    - Forza '--output json' se non specificato.
    - Se metodo 'profile', aggiunge '-P <profile>'.
    """
    cmd_text = user_command.strip()

    # Rimuovi prefisso eseguibile se presente
    cmd_text = re.sub(r'^(?:\s*)(atlas|mongocli)\s+', '', cmd_text)

    # Aggiungi --output json se assente
    if " -o " not in cmd_text and " --output " not in cmd_text:
        cmd_text += " --output json"

    # Profilo: aggiungi flag (non usiamo env per il profilo)
    if method == "profile" and prof:
        cmd_text += f" -P {shlex.quote(prof)}"

    # Split in argv
    user_argv = shlex.split(cmd_text)

    # Argv finale
    return [atlas_bin] + user_argv


def _clean_env_for_child(base_env: dict) -> dict:
    """
    Prepara l'ambiente del processo figlio:
    - Rimuove variabili proxy (no proxy).
    """
    env = base_env.copy()
    # Disabilita completamente l'uso di proxy
    #for k in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy", "NO_PROXY", "no_proxy"):
    #    env.pop(k, None)
    return env


# ======================
# Route HTTP
# ======================
@app.route(route="atlas/exec", methods=["POST"], auth_level=func.AuthLevel.FUNCTION)
def atlas_exec(req: func.HttpRequest) -> func.HttpResponse:
    # Correlation / Request ID
    request_id = (
        req.headers.get("x-correlation-id")
        or req.headers.get("x-request-id")
        or os.urandom(8).hex()
    )

    # Parse body
    try:
        body = req.get_json()
    except Exception:
        return func.HttpResponse(
            json.dumps({"error": "BadRequest", "message": "Corpo JSON non valido", "request_id": request_id}),
            status_code=400, mimetype="application/json"
        )

    # Validate model
    try:
        data = AtlasExecRequest(**body)
    except Exception as e:
        return func.HttpResponse(
            json.dumps({"error": "ValidationError", "message": str(e), "request_id": request_id}),
            status_code=400, mimetype="application/json"
        )

    # Installa/assicurati del binario
    try:
        atlas_bin = _ensure_atlas_cli_installed()
    except Exception as e:
        # Errore dettagliato (no generico), utile per diagnosi
        return func.HttpResponse(
            json.dumps({"error": "AtlasInstallFailed", "message": str(e), "request_id": request_id}),
            status_code=502, mimetype="application/json"
        )

    # Ambiente di esecuzione
    env = _clean_env_for_child(os.environ)

    # Recupero credenziali da Key Vault (se configurate)
    pub = ""
    priv = ""
    prof = data.profile or ATLAS_DEFAULT_PROFILE or ""

    try:
        if ATLAS_PUBLIC_KEY_SECRET_NAME:
            pub = _kv_get(ATLAS_PUBLIC_KEY_SECRET_NAME) or ""
        if ATLAS_PRIVATE_KEY_SECRET_NAME:
            priv = _kv_get(ATLAS_PRIVATE_KEY_SECRET_NAME) or ""
    except Exception as e:
        logger.exception("Errore lettura secret Atlas da KeyVault: %s", e)
        # Espone l'errore per analisi
        return func.HttpResponse(
            json.dumps({"error": "KVError", "message": str(e), "request_id": request_id}),
            status_code=502, mimetype="application/json"
        )

    # Selezione metodo auth (default desiderato: api_key)
    try:
        method = _choose_atlas_auth_method(pub, priv, prof, data.auth_method)
    except Exception as e:
        return func.HttpResponse(
            json.dumps({"error": "AuthSelectionError", "message": str(e), "request_id": request_id}),
            status_code=400, mimetype="application/json"
        )

    # Configura env per il metodo scelto
    if method == "api_key":
        # Atlas CLI: variabili corrette
        env["MONGODB_ATLAS_PUBLIC_API_KEY"] = pub
        env["MONGODB_ATLAS_PRIVATE_API_KEY"] = priv
        # Non usare profilo da env
        env.pop("ATLAS_PROFILE", None)
    elif method == "profile":
        if not prof:
            return func.HttpResponse(
                json.dumps({
                    "error": "MissingProfile",
                    "message": "Profilo Atlas non specificato",
                    "request_id": request_id
                }),
                status_code=400, mimetype="application/json"
            )
        # Non settiamo env di profilo; usiamo flag -P
        env.pop("ATLAS_PROFILE", None)

    # Costruisci argv sicuro (no shell=True)
    try:
        argv = _build_cli_argv(atlas_bin, data.command, method, prof)
    except Exception as e:
        return func.HttpResponse(
            json.dumps({"error": "CommandBuildError", "message": str(e), "request_id": request_id}),
            status_code=400, mimetype="application/json"
        )

    logger.info("Eseguo Atlas CLI (argv): %s", " ".join(shlex.quote(a) for a in argv))

    # Esecuzione
    started_at = time.time()
    try:
        proc = subprocess.run(
            argv,
            shell=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
            timeout=data.timeout_sec
        )
        finished_at = time.time()
        stdout = proc.stdout.decode("utf-8", errors="ignore")
        stderr = proc.stderr.decode("utf-8", errors="ignore")
        exit_code = proc.returncode

        # Mapping status: se il comando fallisce (exit_code != 0) → 400
        http_status = 200 if (isinstance(exit_code, int) and exit_code == 0) else 400

    except subprocess.TimeoutExpired as te:
        finished_at = time.time()
        stdout = (te.stdout.decode("utf-8", errors="ignore") if te.stdout else "")
        stderr = (te.stderr.decode("utf-8", errors="ignore") if te.stderr else "Timeout scaduto")
        exit_code = None
        http_status = 408  # timeout esplicito

    except Exception as e:
        # Errore imprevisto: esponi messaggio originale per analisi (come richiesto)
        finished_at = time.time()
        stdout = ""
        stderr = str(e)
        exit_code = None
        http_status = 500

    resp = {
        "command_executed": data.command.strip(),
        "argv_executed": argv,  # utile per diagnostica
        "auth_mode": method,
        "profile_used": (prof if method == "profile" else ""),
        "exit_status": exit_code,
        "stdout": stdout,
        "stderr": stderr,
        "started_at": started_at,
        "finished_at": finished_at,
        "duration_ms": int((finished_at - started_at) * 1000),
        "request_id": request_id
    }

    return func.HttpResponse(json.dumps(resp), status_code=http_status, mimetype="application/json")
