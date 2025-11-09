import os
import re
import json
import stat
import time
import urllib.request
import subprocess
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

# ======= Modello =======
class AtlasExecRequest(BaseModel):
    command: str = Field(..., description="Comando Atlas CLI (es: 'clusters list')")
    profile: str | None = None
    auth_method: str | None = Field(None, description="api_key|profile|auto")
    timeout_sec: float | None = Field(120.0, description="Timeout in secondi")
    correlation_id: str | None = None

    @validator("timeout_sec")
    def positive_timeout_atlas(cls, v):
        if v is None:
            return 120.0
        if v <= 0:
            raise ValueError("timeout_sec deve essere > 0")
        return v

# ======= Helpers =======
def _ensure_atlas_cli_installed(version: str = None, force: bool = False) -> str:
    ver = version or ATLAS_CLI_VERSION
    target_path = ATLAS_CLI_PATH
    fallback = ATLAS_CLI_FALLBACK_PATH
    try:
        test_dir = os.path.dirname(target_path)
        os.makedirs(test_dir, exist_ok=True)
        if not os.access(test_dir, os.W_OK | os.X_OK):
            logger.warning("Directory %s non scrivibile/exec, uso fallback %s.", test_dir, fallback)
            target_path = fallback
    except Exception as e:
        logger.warning("Errore creazione dir persistente per atlas cli: %s, uso fallback %s.", e, fallback)
        target_path = fallback

    bin_candidate = os.path.join(target_path, "mongocli")
    bin_candidate2 = os.path.join(target_path, "atlas")
    if not force and (os.path.exists(bin_candidate) or os.path.exists(bin_candidate2)):
        if os.path.exists(bin_candidate) and os.access(bin_candidate, os.X_OK):
            return bin_candidate
        if os.path.exists(bin_candidate2) and os.access(bin_candidate2, os.X_OK):
            return bin_candidate2

    url = ATLAS_CLI_DOWNLOAD_URL_TEMPLATE.format(version=ver)
    logger.info("Scaricando Atlas CLI da %s ...", url)
    try:
        tmp_path = target_path + ".tar.gz"
        urllib.request.urlretrieve(url, tmp_path)
        try:
            import tarfile
            with tarfile.open(tmp_path, "r:gz") as tar:
                tar.extractall(path=target_path)
        except Exception as e:
            logger.exception("Errore estrazione atlas cli: %s", e)
            raise

        if os.path.exists(bin_candidate):
            os.chmod(bin_candidate, 0o755)
            return bin_candidate
        if os.path.exists(bin_candidate2):
            os.chmod(bin_candidate2, 0o755)
            return bin_candidate2

        # fallback: primo eseguibile
        for root, _, files in os.walk(target_path):
            for f in files:
                p = os.path.join(root, f)
                try:
                    st = os.stat(p)
                    if st.st_mode & stat.S_IXUSR:
                        return p
                except Exception:
                    pass

        raise RuntimeError("Atlas CLI binario non trovato dopo estrazione")
    except Exception as e:
        logger.exception("Errore durante il download/install di Atlas CLI: %s", e)
        raise RuntimeError(f"Unable to download Atlas CLI: {e}")

def _choose_atlas_auth_method(pub: str, priv: str, prof: str) -> str:
    pref = ATLAS_AUTH_PREFERENCE if ATLAS_AUTH_PREFERENCE in ("api_key", "profile", "auto") else "auto"
    if pref == "api_key":
        if pub and priv: return "api_key"
        raise RuntimeError("ATLAS_AUTH_PREFERENCE=api_key ma API Key mancante")
    if pref == "profile":
        if prof: return "profile"
        raise RuntimeError("ATLAS_AUTH_PREFERENCE=profile ma profile non presente")
    if pub and priv: return "api_key"
    if prof: return "profile"
    return "none"

# ======= Route =======
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
                                 status_code=500, mimetype="application/json")

    env = os.environ.copy()
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
        return func.HttpResponse(json.dumps({"error": "KVError", "message": str(e), "request_id": request_id}),
                                 status_code=500, mimetype="application/json")

    try:
        method = (data.auth_method or "").lower() if data.auth_method else _choose_atlas_auth_method(pub, priv, prof)
    except Exception as e:
        return func.HttpResponse(json.dumps({"error": "AuthSelectionError", "message": str(e), "request_id": request_id}),
                                 status_code=400, mimetype="application/json")

    if method == "api_key":
        env["ATLAS_PUBLIC_KEY"] = pub
        env["ATLAS_PRIVATE_KEY"] = priv
        env.pop("ATLAS_PROFILE", None)
    elif method == "profile":
        if not prof:
            return func.HttpResponse(json.dumps({"error": "MissingProfile", "message": "Profilo Atlas non specificato", "request_id": request_id}),
                                     status_code=400, mimetype="application/json")
        env["ATLAS_PROFILE"] = prof
        env.pop("ATLAS_PUBLIC_KEY", None)
        env.pop("ATLAS_PRIVATE_KEY", None)

    cmd_text = data.command.strip()
    cmd_replaced = re.sub(r'(^|\s)(atlas|mongocli)(\s|$)',
                          lambda m: (m.group(1) or "") + atlas_bin + (m.group(3) or " "),
                          cmd_text, count=1)
    if cmd_replaced == cmd_text:
        cmd_replaced = atlas_bin + " " + cmd_text

    logger.info("Eseguo Atlas CLI: %s", cmd_replaced)
    start = time.time()
    try:
        proc = subprocess.run(cmd_replaced, shell=True, executable="/bin/sh",
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, timeout=data.timeout_sec)
        finished = time.time()
        stdout = proc.stdout.decode("utf-8", errors="ignore")
        stderr = proc.stderr.decode("utf-8", errors="ignore")
        exit_code = proc.returncode
    except subprocess.TimeoutExpired as te:
        finished = time.time()
        stdout = te.stdout.decode("utf-8", errors="ignore") if te.stdout else ""
        stderr = te.stderr.decode("utf-8", errors="ignore") if te.stderr else ""
        exit_code = None
        logger.warning("Atlas CLI timeout")
    except Exception as e:
        finished = time.time()
        stdout = ""
        stderr = str(e)
        exit_code = None
        logger.exception("Errore esecuzione Atlas CLI")

    resp = {
        "command_executed": data.command.strip(),
        "auth_mode": method,
        "profile_used": env.get("ATLAS_PROFILE", ""),
        "exit_status": exit_code,
        "stdout": stdout,
        "stderr": stderr,
        "started_at": start,
        "finished_at": finished,
        "duration_ms": int((finished - start) * 1000),
        "request_id": request_id
    }
    return func.HttpResponse(json.dumps(resp), status_code=200, mimetype="application/json")