import os
import json
import time
import stat
import base64
import re
import urllib.request
import tempfile
import subprocess
import azure.functions as func
import yaml
from pydantic import BaseModel, Field, validator
from typing import Optional

from .app import app, logger
from .keyvault import _kv_get
from .settings import (
    DEFAULT_KUBECTL_VERSION, KUBECTL_DOWNLOAD_URL_TEMPLATE,
    KUBECTL_PATH_DEFAULT, KUBECTL_FALLBACK_PATH,
    K8S_AUTH_PREFERENCE, KUBE_CONFIG_SECRET_NAME, KUBE_TOKEN_SECRET_NAME,
    KUBE_USERNAME_SECRET_NAME, KUBE_PASSWORD_SECRET_NAME
)

# ======= Modello =======
class K8SCommandRequest(BaseModel):
    api_server: str = Field(..., description='API server (es: https://1.2.3.4:6443)')
    auth_method: str = Field('kubeconfig', description="Metodo di autenticazione: kubeconfig|token|userpass")
    command: str = Field(..., description='Comando kubectl testuale (es: "get pods -A")')
    kubeconfig: Optional[str] = Field(None, description='Contenuto kubeconfig (yaml o base64)')
    token: Optional[str] = None
    username: Optional[str] = None
    password: Optional[str] = None
    timeout_sec: Optional[float] = Field(60.0, description="Timeout in secondi")
    correlation_id: Optional[str] = None

    @validator("timeout_sec")
    def positive_timeout_k8s(cls, v):
        if v is None:
            return 60.0
        if v <= 0:
            raise ValueError("timeout_sec deve essere > 0")
        return v

# ======= Helpers =======
def _ensure_kubectl_installed(version: str = DEFAULT_KUBECTL_VERSION, force: bool = False) -> str:
    target_path = KUBECTL_PATH_DEFAULT
    try:
        test_dir = os.path.dirname(target_path)
        os.makedirs(test_dir, exist_ok=True)
        if not os.access(test_dir, os.W_OK | os.X_OK):
            logger.warning("Directory %s non scrivibile/exec, uso fallback %s.", test_dir, KUBECTL_FALLBACK_PATH)
            target_path = KUBECTL_FALLBACK_PATH
    except Exception as e:
        logger.warning("Errore creazione dir persistente: %s, uso fallback %s.", e, KUBECTL_FALLBACK_PATH)
        target_path = KUBECTL_FALLBACK_PATH

    if os.path.exists(target_path) and not force:
        try:
            st = os.stat(target_path)
            if st.st_mode & stat.S_IXUSR:
                return target_path
        except Exception:
            pass

    url = KUBECTL_DOWNLOAD_URL_TEMPLATE.format(version=version)
    logger.info("Scaricando kubectl da %s ...", url)
    try:
        tmp_path = target_path + ".download"
        urllib.request.urlretrieve(url, tmp_path)
        os.chmod(tmp_path, 0o755)
        os.replace(tmp_path, target_path)
        return target_path
    except Exception as e:
        logger.exception("Errore durante il download di kubectl: %s", e)
        raise RuntimeError(f"Unable to download kubectl: {e}")

def _choose_k8s_auth_method(kc: str, tok: str, usr: str, pwd: str) -> str:
    pref = K8S_AUTH_PREFERENCE if K8S_AUTH_PREFERENCE in ("auto", "kubeconfig", "token", "userpass") else "auto"
    if pref == "kubeconfig":
        if kc: return "kubeconfig"
        raise RuntimeError("K8S_AUTH_PREFERENCE=kubeconfig ma kubeconfig non presente")
    if pref == "token":
        if tok: return "token"
        raise RuntimeError("K8S_AUTH_PREFERENCE=token ma token non presente")
    if pref == "userpass":
        if usr and pwd: return "userpass"
        raise RuntimeError("K8S_AUTH_PREFERENCE=userpass ma username/password non presenti")
    if kc: return "kubeconfig"
    if tok: return "token"
    if usr and pwd: return "userpass"
    raise RuntimeError("Nessuna credenziale Kubernetes disponibile")

def _build_kubeconfig_from_parts(api_server: str, token: str = None, username: str = None, password: str = None) -> str:
    cfg = {
        "apiVersion": "v1",
        "kind": "Config",
        "clusters": [{"name": "cluster", "cluster": {"server": api_server, "insecure-skip-tls-verify": True}}],
        "contexts": [{"name": "ctx", "context": {"cluster": "cluster", "user": "user"}}],
        "current-context": "ctx",
        "users": [{"name": "user", "user": {}}]
    }
    user = cfg["users"][0]["user"]
    if token:
        user["token"] = token
    elif username and password:
        user["username"] = username
        user["password"] = password
    else:
        raise ValueError("token o username/password richiesti per auth_method diverso da kubeconfig")
    return yaml.safe_dump(cfg)

def _write_temp_kubeconfig(content: str) -> str:
    tf = tempfile.NamedTemporaryFile(delete=False, suffix=".yaml")
    tf.write(content.encode("utf-8"))
    tf.flush()
    tf.close()
    return tf.name

# ======= Route =======
@app.route(route="k8s/exec", methods=["POST"], auth_level=func.AuthLevel.FUNCTION)
def kubectl_exec(req: func.HttpRequest) -> func.HttpResponse:
    request_id = req.headers.get("x-correlation-id") or req.headers.get("x-request-id") or os.urandom(8).hex()
    try:
        body = req.get_json()
    except Exception:
        return func.HttpResponse(json.dumps({"error": "BadRequest", "message": "Corpo JSON non valido", "request_id": request_id}),
                                 status_code=400, mimetype="application/json")
    try:
        data = K8SCommandRequest(**body)
    except Exception as e:
        return func.HttpResponse(json.dumps({"error": "ValidationError", "message": str(e), "request_id": request_id}),
                                 status_code=400, mimetype="application/json")

    kc = data.kubeconfig or ""
    tok = data.token or ""
    usr = data.username or ""
    pwd = data.password or ""

    if not kc and KUBE_CONFIG_SECRET_NAME:
        kc = _kv_get(KUBE_CONFIG_SECRET_NAME) or ""
    if not tok and KUBE_TOKEN_SECRET_NAME:
        tok = _kv_get(KUBE_TOKEN_SECRET_NAME) or ""
    if not usr and KUBE_USERNAME_SECRET_NAME:
        usr = _kv_get(KUBE_USERNAME_SECRET_NAME) or ""
    if not pwd and KUBE_PASSWORD_SECRET_NAME:
        pwd = _kv_get(KUBE_PASSWORD_SECRET_NAME) or ""

    try:
        auth_method = data.auth_method or _choose_k8s_auth_method(kc, tok, usr, pwd)
    except Exception as e:
        return func.HttpResponse(json.dumps({"error": "AuthSelectionError", "message": str(e), "request_id": request_id}),
                                 status_code=400, mimetype="application/json")

    kubeconfig_path = None
    try:
        if auth_method == "kubeconfig":
            s = kc.strip()
            try:
                if not s.startswith("apiVersion") and not s.startswith("kind") and "clusters:" not in s:
                    kc = base64.b64decode(s).decode("utf-8")
            except Exception:
                pass
            kubeconfig_path = _write_temp_kubeconfig(kc)
        elif auth_method == "token":
            kube_yaml = _build_kubeconfig_from_parts(data.api_server, token=tok)
            kubeconfig_path = _write_temp_kubeconfig(kube_yaml)
        elif auth_method == "userpass":
            kube_yaml = _build_kubeconfig_from_parts(data.api_server, username=usr, password=pwd)
            kubeconfig_path = _write_temp_kubeconfig(kube_yaml)
        else:
            return func.HttpResponse(json.dumps({"error": "BadAuthMethod", "message": f"auth_method non valido: {auth_method}", "request_id": request_id}),
                                     status_code=400, mimetype="application/json")
    except Exception as e:
        logger.exception("Errore nella costruzione del kubeconfig")
        return func.HttpResponse(json.dumps({"error": "KubeConfigError", "message": str(e), "request_id": request_id}),
                                 status_code=500, mimetype="application/json")

    try:
        kubectl_path = _ensure_kubectl_installed()
    except Exception as e:
        return func.HttpResponse(json.dumps({"error": "KubectlInstallFailed", "message": str(e), "request_id": request_id}),
                                 status_code=500, mimetype="application/json")

    env = os.environ.copy()
    env["KUBECONFIG"] = kubeconfig_path

    cmd = data.command.strip()
    # Inserisce il path kubectl se l'utente ha scritto "kubectl ..."
    cmd_replaced = re.sub(r'(^|\s)kubectl(\s|$)',
                          lambda m: (m.group(1) or "") + kubectl_path + (m.group(2) or " "),
                          cmd, count=1)
    if cmd_replaced == cmd:
        cmd_replaced = kubectl_path + " " + cmd

    logger.info("Eseguo comando: %s", cmd_replaced)
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
        logger.warning("kubectl command timeout")
    except Exception as e:
        finished = time.time()
        stdout = ""
        stderr = str(e)
        exit_code = None
        logger.exception("Errore esecuzione kubectl")

    try:
        if kubeconfig_path and os.path.exists(kubeconfig_path):
            os.unlink(kubeconfig_path)
    except Exception:
        pass

    resp = {
        "command_executed": data.command.strip(),
        "exit_status": exit_code,
        "stdout": stdout,
        "stderr": stderr,
        "stdout_truncated": False,
        "stderr_truncated": False,
        "started_at": start,
        "finished_at": finished,
        "duration_ms": int((finished - start) * 1000),
        "request_id": request_id
    }
    return func.HttpResponse(json.dumps(resp), status_code=200, mimetype="application/json")